use hbb_common::{
    anyhow::{anyhow, bail, Context},
    base64::{engine::general_purpose::STANDARD, Engine as _},
    config::{Config, LocalConfig},
    sodiumoxide::crypto::{auth, secretbox, sign},
    tls::TlsType,
    ResultType,
};
use serde::Deserialize;
use std::{collections::HashMap, convert::TryInto, time::Duration};

const ENVELOPE_VERSION: u32 = 1;
const CACHE_OPTION: &str = "android-provisioning-bootstrap-envelope";
const POLICY_CACHE_OPTION: &str = "android-provisioning-policy-envelope";
pub const UNATTENDED_ENABLED_OPTION: &str = "android-unattended-enabled";
pub const UNATTENDED_ROOT_OPTION: &str = "android-unattended-root-command";
pub const UNATTENDED_REVISION_OPTION: &str = "android-unattended-policy-revision";
pub const POLICY_REVISION_OPTION: &str = "android-provisioning-policy-revision";
pub const DEVICE_ID_OPTION: &str = "android-provisioning-device-id";
const CONNECTION_ID_REQUESTED_OPTION: &str = "android-provisioning-connection-id-requested";
const CONNECTION_ID_ACTIVE_OPTION: &str = "android-provisioning-connection-id-active";
const CONNECTION_ID_STATUS_OPTION: &str = "android-provisioning-connection-id-status";
const CONNECTION_ID_REVISION_OPTION: &str = "android-provisioning-connection-id-revision";
const CONNECTION_ID_ERROR_OPTION: &str = "android-provisioning-connection-id-error";
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
    device_id: i64,
    uuid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionIdPolicy {
    requested_id: String,
    status: String,
    revision: i64,
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

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ServerProfilePolicy {
    enabled: bool,
    id_server: String,
    relay_server: String,
    key: String,
    permanent_password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPayload {
    version: u32,
    revision: u64,
    issued_at: i64,
    expires_at: i64,
    target: PolicyTarget,
    connection_id: ConnectionIdPolicy,
    android: AndroidPolicy,
    #[serde(default)]
    server_profile: ServerProfilePolicy,
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

fn decode_policy(bytes: &[u8], device_id: Option<i64>, uuid: &str) -> ResultType<PolicyPayload> {
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
    if payload.version != 2
        || payload.revision == 0
        || payload.issued_at > now + 300
        || payload.expires_at <= now
        || payload.expires_at <= payload.issued_at
        || payload.target.device_id <= 0
        || device_id.map_or(false, |id| payload.target.device_id != id)
        || payload.target.uuid != uuid
        || !valid_root_command(&payload.android.unattended.root_command)
        || !valid_connection_id_policy(&payload.connection_id)
    {
        bail!("Invalid provisioning policy")
    }
    validate_server_profile(&payload.server_profile)?;
    Ok(payload)
}

fn valid_connection_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (6..=16).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_connection_id_policy(policy: &ConnectionIdPolicy) -> bool {
    match policy.status.as_str() {
        "" => policy.requested_id.is_empty() && policy.revision == 0,
        "pending" => valid_connection_id(&policy.requested_id) && policy.revision > 0,
        _ => false,
    }
}

fn validate_server_profile(profile: &ServerProfilePolicy) -> ResultType<()> {
    if !profile.enabled {
        return Ok(());
    }
    if profile.id_server.trim().is_empty()
        || profile.id_server != profile.id_server.trim()
        || profile.relay_server != profile.relay_server.trim()
        || profile.id_server.chars().any(char::is_whitespace)
        || profile.relay_server.chars().any(char::is_whitespace)
        || profile.id_server.len() > 255
        || profile.relay_server.len() > 255
        || profile.key.len() > 255
        || profile.permanent_password.len() > 255
    {
        bail!("Invalid hidden server profile")
    }
    Ok(())
}

fn valid_root_command(value: &str) -> bool {
    value == "auto"
        || value != "disabled"
            && !value.is_empty()
            && value.len() <= 255
            && !value
                .chars()
                .any(|char| char.is_whitespace() || char.is_control())
}

fn current_provisioning_api_server() -> String {
    cached_bootstrap()
        .ok()
        .flatten()
        .map(|(payload, _)| payload.provisioning_api_server)
        .unwrap_or_default()
}

fn activate_server_profile(profile: &ServerProfilePolicy) -> bool {
    let mut options = HashMap::new();
    if profile.enabled {
        options.insert(
            "custom-rendezvous-server".to_owned(),
            profile.id_server.clone(),
        );
        options.insert("relay-server".to_owned(), profile.relay_server.clone());
        options.insert("api-server".to_owned(), current_provisioning_api_server());
        options.insert("key".to_owned(), profile.key.clone());
    }
    hbb_common::config::Config::set_hidden_server_profile(
        options,
        if profile.enabled {
            profile.permanent_password.clone()
        } else {
            String::new()
        },
    )
}

pub async fn apply_policy(encoded: &str, device_id: i64, uuid: &str) -> ResultType<u64> {
    let bytes = STANDARD
        .decode(encoded)
        .context("Invalid provisioning policy encoding")?;
    let payload = decode_policy(&bytes, Some(device_id), uuid)?;
    let cached_revision = LocalConfig::get_option(POLICY_REVISION_OPTION)
        .parse::<u64>()
        .unwrap_or(0);
    if payload.revision < cached_revision {
        bail!("Provisioning policy revision rollback")
    }
    LocalConfig::set_option(POLICY_CACHE_OPTION.to_owned(), encoded.to_owned());
    LocalConfig::set_option(
        POLICY_REVISION_OPTION.to_owned(),
        payload.revision.to_string(),
    );
    let unattended_enabled = if payload.android.unattended.enabled {
        "Y"
    } else {
        "N"
    };
    if LocalConfig::get_option(UNATTENDED_ENABLED_OPTION) != unattended_enabled
        || LocalConfig::get_option(UNATTENDED_ROOT_OPTION)
            != payload.android.unattended.root_command
    {
        LocalConfig::set_option(
            UNATTENDED_ENABLED_OPTION.to_owned(),
            unattended_enabled.to_owned(),
        );
        LocalConfig::set_option(
            UNATTENDED_ROOT_OPTION.to_owned(),
            payload.android.unattended.root_command,
        );
        LocalConfig::set_option(
            UNATTENDED_REVISION_OPTION.to_owned(),
            payload.revision.to_string(),
        );
    }
    let profile_changed = activate_server_profile(&payload.server_profile);
    let connection_id_changed = apply_connection_id(&payload.connection_id).await;
    if (profile_changed || connection_id_changed)
        && !hbb_common::config::Config::is_manual_server_profile()
    {
        crate::rendezvous_mediator::RendezvousMediator::restart();
    }
    Ok(payload.revision)
}

pub fn restore_cached_policy(uuid: &str) -> ResultType<()> {
    let encoded = LocalConfig::get_option(POLICY_CACHE_OPTION);
    if encoded.is_empty() {
        return Ok(());
    }
    let bytes = STANDARD
        .decode(&encoded)
        .context("Invalid cached provisioning policy")?;
    let device_id = LocalConfig::get_option(DEVICE_ID_OPTION)
        .parse::<i64>()
        .context("Missing cached device identity")?;
    let payload = decode_policy(&bytes, Some(device_id), uuid)?;
    activate_server_profile(&payload.server_profile);
    Ok(())
}

async fn apply_connection_id(policy: &ConnectionIdPolicy) -> bool {
    if policy.status != "pending" || policy.requested_id.is_empty() {
        return false;
    }
    let active_id = Config::get_id();
    LocalConfig::set_option(
        CONNECTION_ID_REQUESTED_OPTION.to_owned(),
        policy.requested_id.clone(),
    );
    if active_id == policy.requested_id {
        store_connection_id_result(
            &policy.requested_id,
            &active_id,
            "applied",
            policy.revision,
            "",
        );
        return false;
    }
    if Config::is_manual_server_profile() {
        store_connection_id_result(
            &policy.requested_id,
            &active_id,
            "failed",
            policy.revision,
            "manual_server_profile",
        );
        return false;
    }
    match register_connection_id(&policy.requested_id).await {
        Ok(()) => {
            crate::rendezvous_mediator::reset_needs_deploy_notification();
            store_connection_id_result(
                &policy.requested_id,
                &policy.requested_id,
                "applied",
                policy.revision,
                "",
            );
            true
        }
        Err(error) => {
            store_connection_id_result(
                &policy.requested_id,
                &active_id,
                "failed",
                policy.revision,
                &error,
            );
            false
        }
    }
}

async fn register_connection_id(id: &str) -> Result<(), String> {
    if Config::get_rendezvous_servers().is_empty() {
        return Err("id_server_unavailable".to_owned());
    }
    let old_id = Config::get_id();
    match crate::ui_interface::change_id_shared_(id.to_owned(), old_id).await {
        "" => Ok(()),
        "Not available" => Err("id_taken".to_owned()),
        "Too frequent" => Err("id_registration_too_frequent".to_owned()),
        "server_not_support" => Err("id_server_not_supported".to_owned()),
        "Invalid format" => Err("invalid_connection_id".to_owned()),
        "Failed to connect to rendezvous server" => Err("id_server_unavailable".to_owned()),
        "Server error" => Err("id_server_error".to_owned()),
        _ => Err("id_registration_failed".to_owned()),
    }
}

fn store_connection_id_result(
    requested_id: &str,
    active_id: &str,
    status: &str,
    revision: i64,
    error: &str,
) {
    LocalConfig::set_option(
        CONNECTION_ID_REQUESTED_OPTION.to_owned(),
        requested_id.to_owned(),
    );
    LocalConfig::set_option(CONNECTION_ID_ACTIVE_OPTION.to_owned(), active_id.to_owned());
    LocalConfig::set_option(CONNECTION_ID_STATUS_OPTION.to_owned(), status.to_owned());
    LocalConfig::set_option(
        CONNECTION_ID_REVISION_OPTION.to_owned(),
        revision.to_string(),
    );
    LocalConfig::set_option(CONNECTION_ID_ERROR_OPTION.to_owned(), error.to_owned());
}

pub fn connection_id_report() -> Option<serde_json::Value> {
    let status = LocalConfig::get_option(CONNECTION_ID_STATUS_OPTION);
    if status != "applied" && status != "failed" {
        return None;
    }
    Some(serde_json::json!({
        "requested_id": LocalConfig::get_option(CONNECTION_ID_REQUESTED_OPTION),
        "active_id": LocalConfig::get_option(CONNECTION_ID_ACTIVE_OPTION),
        "status": status,
        "revision": LocalConfig::get_option(CONNECTION_ID_REVISION_OPTION).parse::<i64>().unwrap_or(0),
        "last_error": LocalConfig::get_option(CONNECTION_ID_ERROR_OPTION),
    }))
}

pub fn mark_connection_id_reported() {
    LocalConfig::set_option(CONNECTION_ID_STATUS_OPTION.to_owned(), String::new());
    LocalConfig::set_option(CONNECTION_ID_ERROR_OPTION.to_owned(), String::new());
}

pub fn server_profile_source() -> &'static str {
    if hbb_common::config::Config::is_manual_server_profile() {
        "manual"
    } else if hbb_common::config::Config::has_hidden_server_profile() {
        "provisioned"
    } else if is_configured() {
        "waiting"
    } else {
        "public"
    }
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
    use super::{signature_message, valid_connection_id, valid_root_command};

    #[test]
    fn signature_message_binds_purpose_and_key_id() {
        let first = signature_message(1, "bootstrap", "android-v1", &[1; 24], &[2; 8]);
        let second = signature_message(1, "policy", "android-v1", &[1; 24], &[2; 8]);
        assert_ne!(first, second);
    }

    #[test]
    fn root_executor_accepts_a_single_name_or_path() {
        for value in ["auto", "su", "testsu", "/system/xbin/custom-su"] {
            assert!(valid_root_command(value));
        }
        for value in ["", "disabled", "su -c", "/system/bin/su\n"] {
            assert!(!valid_root_command(value));
        }
    }

    #[test]
    fn managed_connection_id_is_lowercase_ascii() {
        for value in ["shop23", "shop23-a01", "a12345"] {
            assert!(valid_connection_id(value));
        }
        for value in [
            "short",
            "Shop23",
            "1shop23",
            "shop_23",
            "商店-a01",
            "shop-id-that-is-too-long",
        ] {
            assert!(!valid_connection_id(value));
        }
    }
}
