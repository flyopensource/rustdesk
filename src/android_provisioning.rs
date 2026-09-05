use hbb_common::{
    anyhow::{anyhow, bail, Context},
    base64::{engine::general_purpose::STANDARD, Engine as _},
    config::LocalConfig,
    sodiumoxide::crypto::{auth, secretbox, sign},
    tls::TlsType,
    ResultType,
};
use serde::Deserialize;
use std::{convert::TryInto, time::Duration};

const ENVELOPE_VERSION: u32 = 1;
const CACHE_OPTION: &str = "android-provisioning-bootstrap-envelope";
const POLICY_CACHE_OPTION: &str = "android-provisioning-policy-envelope";
pub const UNATTENDED_ENABLED_OPTION: &str = "android-unattended-enabled";
pub const UNATTENDED_ROOT_OPTION: &str = "android-unattended-root-command";
pub const UNATTENDED_REVISION_OPTION: &str = "android-unattended-policy-revision";
const MAX_ENVELOPE_SIZE: usize = 64 * 1024;
const MAX_PLAINTEXT_SIZE: usize = 16 * 1024;
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

lazy_static::lazy_static! {
    static ref LAST_REFRESH: std::sync::Mutex<Option<std::time::Instant>> = Default::default();
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionEnvelope {
    version: u32,
    purpose: String,
    key_id: String,
    nonce: String,
    ciphertext: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapPayload {
    version: u32,
    revision: u64,
    issued_at: i64,
    expires_at: i64,
    provisioning_api_server: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTarget {
    rustdesk_id: String,
    uuid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnattendedPolicy {
    enabled: bool,
    root_command: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AndroidPolicy {
    unattended: UnattendedPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPayload {
    version: u32,
    revision: u64,
    issued_at: i64,
    expires_at: i64,
    target: PolicyTarget,
    android: AndroidPolicy,
}

pub fn is_configured() -> bool {
    option_env!("RUD_CFG_URL")
        .map(str::trim)
        .unwrap_or_default()
        != ""
}

pub fn device_enrollment_key() -> ResultType<auth::Key> {
    decode_fixed::<{ auth::KEYBYTES }>(
        option_env!("RUD_DEVICE_ENROLLMENT_KEY_B64")
            .map(str::trim)
            .unwrap_or_default(),
        "device enrollment key",
    )
    .map(auth::Key)
}

fn configured_key_id() -> &'static str {
    option_env!("RUD_CFG_KEY_ID")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("android-v1")
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> ResultType<[u8; N]> {
    if value.is_empty() {
        bail!("Missing provisioning {label}")
    }
    STANDARD
        .decode(value)
        .with_context(|| format!("Failed to decode provisioning {label}"))?
        .try_into()
        .map_err(|_| anyhow!("Invalid provisioning {label} length"))
}

fn signature_message(
    version: u32,
    purpose: &str,
    key_id: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(8 + purpose.len() + key_id.len() + nonce.len() + ciphertext.len());
    message.extend_from_slice(b"RUD1");
    message.extend_from_slice(&version.to_be_bytes());
    message.extend_from_slice(purpose.as_bytes());
    message.push(0);
    message.extend_from_slice(key_id.as_bytes());
    message.push(0);
    message.extend_from_slice(nonce);
    message.extend_from_slice(ciphertext);
    message
}

fn validate_server_url(value: &str) -> ResultType<String> {
    let mut url = reqwest::Url::parse(value).context("Invalid provisioning API URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        bail!("Invalid provisioning API URL")
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn decode_bootstrap(bytes: &[u8]) -> ResultType<BootstrapPayload> {
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_SIZE {
        bail!("Invalid provisioning bootstrap size")
    }
    let envelope: ProvisionEnvelope =
        serde_json::from_slice(bytes).context("Invalid provisioning envelope")?;
    if envelope.version != ENVELOPE_VERSION
        || envelope.purpose != "bootstrap"
        || envelope.key_id != configured_key_id()
    {
        bail!("Unsupported provisioning envelope")
    }
    let nonce = decode_fixed::<{ secretbox::NONCEBYTES }>(&envelope.nonce, "nonce")?;
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext)
        .context("Failed to decode provisioning ciphertext")?;
    let signature = decode_fixed::<{ sign::SIGNATUREBYTES }>(&envelope.signature, "signature")?;
    let public_key = decode_fixed::<{ sign::PUBLICKEYBYTES }>(
        option_env!("RUD_CFG_VERIFY_PUBLIC_KEY_B64")
            .map(str::trim)
            .unwrap_or_default(),
        "verify public key",
    )?;
    let message = signature_message(
        envelope.version,
        &envelope.purpose,
        &envelope.key_id,
        &nonce,
        &ciphertext,
    );
    let signature = sign::Signature::from_bytes(&signature)
        .map_err(|_| anyhow!("Invalid provisioning signature"))?;
    if !sign::verify_detached(&signature, &message, &sign::PublicKey(public_key)) {
        bail!("Provisioning signature mismatch")
    }
    let secret_key = decode_fixed::<{ secretbox::KEYBYTES }>(
        option_env!("RUD_CFG_SECRETBOX_KEY_B64")
            .map(str::trim)
            .unwrap_or_default(),
        "SecretBox key",
    )?;
    let plaintext = secretbox::open(
        &ciphertext,
        &secretbox::Nonce(nonce),
        &secretbox::Key(secret_key),
    )
    .map_err(|_| anyhow!("Provisioning decryption failed"))?;
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        bail!("Invalid provisioning payload size")
    }
    let mut payload: BootstrapPayload =
        serde_json::from_slice(&plaintext).context("Invalid provisioning payload")?;
    let now = hbb_common::get_time() / 1000;
    if payload.version != ENVELOPE_VERSION
        || payload.revision == 0
        || payload.issued_at > now + 300
        || payload.expires_at <= now
        || payload.expires_at <= payload.issued_at
    {
        bail!("Invalid provisioning payload validity")
    }
    payload.provisioning_api_server = validate_server_url(&payload.provisioning_api_server)?;
    Ok(payload)
}

fn decode_policy(bytes: &[u8], id: &str, uuid: &str) -> ResultType<PolicyPayload> {
    if bytes.is_empty() || bytes.len() > 256 * 1024 {
        bail!("Invalid provisioning policy size")
    }
    let envelope: ProvisionEnvelope =
        serde_json::from_slice(bytes).context("Invalid provisioning policy envelope")?;
    if envelope.version != ENVELOPE_VERSION
        || envelope.purpose != "policy"
        || envelope.key_id != configured_key_id()
    {
        bail!("Unsupported provisioning policy envelope")
    }
    let nonce = decode_fixed::<{ secretbox::NONCEBYTES }>(&envelope.nonce, "policy nonce")?;
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext)
        .context("Failed to decode provisioning policy ciphertext")?;
    let signature =
        decode_fixed::<{ sign::SIGNATUREBYTES }>(&envelope.signature, "policy signature")?;
    let public_key = decode_fixed::<{ sign::PUBLICKEYBYTES }>(
        option_env!("RUD_CFG_VERIFY_PUBLIC_KEY_B64")
            .map(str::trim)
            .unwrap_or_default(),
        "verify public key",
    )?;
    let message = signature_message(
        envelope.version,
        &envelope.purpose,
        &envelope.key_id,
        &nonce,
        &ciphertext,
    );
    let signature = sign::Signature::from_bytes(&signature)
        .map_err(|_| anyhow!("Invalid provisioning policy signature"))?;
    if !sign::verify_detached(&signature, &message, &sign::PublicKey(public_key)) {
        bail!("Provisioning policy signature mismatch")
    }
    let secret_key = decode_fixed::<{ secretbox::KEYBYTES }>(
        option_env!("RUD_CFG_SECRETBOX_KEY_B64")
            .map(str::trim)
            .unwrap_or_default(),
        "SecretBox key",
    )?;
    let plaintext = secretbox::open(
        &ciphertext,
        &secretbox::Nonce(nonce),
        &secretbox::Key(secret_key),
    )
    .map_err(|_| anyhow!("Provisioning policy decryption failed"))?;
    let payload: PolicyPayload =
        serde_json::from_slice(&plaintext).context("Invalid provisioning policy payload")?;
    let now = hbb_common::get_time() / 1000;
    if payload.version != ENVELOPE_VERSION
        || payload.revision == 0
        || payload.issued_at > now + 300
        || payload.expires_at <= now
        || payload.expires_at <= payload.issued_at
        || payload.target.rustdesk_id != id
        || payload.target.uuid != uuid
        || !matches!(
            payload.android.unattended.root_command.as_str(),
            "auto" | "su" | "testsu" | "disabled"
        )
    {
        bail!("Invalid provisioning policy")
    }
    Ok(payload)
}

pub fn apply_policy(encoded: &str, id: &str, uuid: &str) -> ResultType<u64> {
    let bytes = STANDARD
        .decode(encoded)
        .context("Invalid provisioning policy encoding")?;
    let payload = decode_policy(&bytes, id, uuid)?;
    let cached_revision = LocalConfig::get_option(UNATTENDED_REVISION_OPTION)
        .parse::<u64>()
        .unwrap_or(0);
    if payload.revision < cached_revision {
        bail!("Provisioning policy revision rollback")
    }
    LocalConfig::set_option(POLICY_CACHE_OPTION.to_owned(), encoded.to_owned());
    LocalConfig::set_option(
        UNATTENDED_ENABLED_OPTION.to_owned(),
        if payload.android.unattended.enabled {
            "Y"
        } else {
            "N"
        }
        .to_owned(),
    );
    LocalConfig::set_option(
        UNATTENDED_ROOT_OPTION.to_owned(),
        payload.android.unattended.root_command,
    );
    LocalConfig::set_option(
        UNATTENDED_REVISION_OPTION.to_owned(),
        payload.revision.to_string(),
    );
    Ok(payload.revision)
}

fn cached_bootstrap() -> ResultType<Option<(BootstrapPayload, Vec<u8>)>> {
    let encoded = LocalConfig::get_option(CACHE_OPTION);
    if encoded.is_empty() {
        return Ok(None);
    }
    let bytes = STANDARD
        .decode(encoded)
        .context("Invalid cached provisioning bootstrap")?;
    let payload = decode_bootstrap(&bytes)?;
    Ok(Some((payload, bytes)))
}

fn should_refresh() -> bool {
    let mut last_refresh = LAST_REFRESH.lock().unwrap();
    if last_refresh
        .map(|instant| instant.elapsed() < REFRESH_INTERVAL)
        .unwrap_or(false)
    {
        return false;
    }
    *last_refresh = Some(std::time::Instant::now());
    true
}

async fn download_bootstrap(url: &str) -> ResultType<Vec<u8>> {
    let parsed = reqwest::Url::parse(url).context("Invalid provisioning bootstrap URL")?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
    {
        bail!("Invalid provisioning bootstrap URL")
    }
    let client = crate::hbbs_http::create_http_client_async_no_redirect(TlsType::Rustls, false);
    let mut response = client.get(url).send().await?;
    let final_url = response.url();
    if final_url.scheme() != parsed.scheme()
        || final_url.host_str() != parsed.host_str()
        || final_url.port_or_known_default() != parsed.port_or_known_default()
    {
        bail!("Provisioning bootstrap redirected to a different origin")
    }
    if response.status() != reqwest::StatusCode::OK {
        bail!("Provisioning bootstrap HTTP status is not 200")
    }
    if response
        .content_length()
        .map(|size| size > MAX_ENVELOPE_SIZE as u64)
        == Some(true)
    {
        bail!("Provisioning bootstrap is too large")
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_ENVELOPE_SIZE {
            bail!("Provisioning bootstrap is too large")
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub async fn provisioning_api_server() -> String {
    if !is_configured() {
        return String::new();
    }
    let cached = match cached_bootstrap() {
        Ok(value) => value,
        Err(error) => {
            hbb_common::log::warn!("Cached provisioning bootstrap rejected: {}", error);
            None
        }
    };
    if !should_refresh() {
        return cached
            .map(|(payload, _)| payload.provisioning_api_server)
            .unwrap_or_default();
    }
    let url = option_env!("RUD_CFG_URL")
        .map(str::trim)
        .unwrap_or_default();
    match download_bootstrap(url).await.and_then(|bytes| {
        let payload = decode_bootstrap(&bytes)?;
        Ok((payload, bytes))
    }) {
        Ok((payload, bytes)) => {
            let cached_revision = cached
                .as_ref()
                .map(|(payload, _)| payload.revision)
                .unwrap_or(0);
            if payload.revision > cached_revision {
                LocalConfig::set_option(CACHE_OPTION.to_owned(), STANDARD.encode(bytes));
                payload.provisioning_api_server
            } else {
                cached
                    .map(|(payload, _)| payload.provisioning_api_server)
                    .unwrap_or_default()
            }
        }
        Err(error) => {
            hbb_common::log::warn!("Provisioning bootstrap refresh failed: {}", error);
            cached
                .map(|(payload, _)| payload.provisioning_api_server)
                .unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::signature_message;

    #[test]
    fn signature_message_binds_purpose_and_key_id() {
        let first = signature_message(1, "bootstrap", "android-v1", &[1; 24], &[2; 8]);
        let second = signature_message(1, "policy", "android-v1", &[1; 24], &[2; 8]);
        assert_ne!(first, second);
    }
}
