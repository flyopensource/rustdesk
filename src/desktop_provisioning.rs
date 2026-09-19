use hbb_common::{
    anyhow::{anyhow, bail, Context},
    base64::{engine::general_purpose::STANDARD, Engine as _},
    config::{load_path, store_path, Config},
    sodiumoxide::crypto::{box_, hash::sha256, sealedbox, sign},
    ResultType,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{convert::TryInto, path::Path};

const IDENTITY_FILE: &str = "desktop_management.toml";
const ENVELOPE_VERSION: u32 = 1;
const MAX_TOKEN_SIZE: u64 = 4096;
const MAX_ENVELOPE_SIZE: usize = 256 * 1024;
const MAX_PASSWORD_SIZE: usize = 255;

lazy_static::lazy_static! {
    static ref IDENTITY_LOCK: std::sync::Mutex<()> = Default::default();
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct DesktopIdentity {
    api_server: String,
    rustdesk_id: String,
    uuid: String,
    device_id: i64,
    next_sequence: i64,
    sign_public_key: String,
    sign_secret_key: String,
    box_public_key: String,
    box_secret_key: String,
    policy_verify_key_id: String,
    policy_verify_public_key: String,
    policy_revision: i64,
    password_status: String,
    permanent_password_set: bool,
    password_error: String,
    enrollment_request_id: String,
    enrollment_token: String,
    enrollment_timestamp: i64,
}

#[derive(Debug, Deserialize)]
struct RegistrationResponse {
    accepted: bool,
    #[serde(default)]
    device_id: i64,
    #[serde(default)]
    last_sequence: i64,
    #[serde(default)]
    policy_verify_key_id: String,
    #[serde(default)]
    policy_verify_public_key: String,
    #[serde(default)]
    server_time: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEnvelope {
    version: u32,
    purpose: String,
    key_id: String,
    device_id: i64,
    revision: i64,
    ciphertext: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTarget {
    device_id: i64,
    rustdesk_id: String,
    uuid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnattendedPolicy {
    password_action: String,
    permanent_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopPolicy {
    unattended: UnattendedPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPayload {
    version: u32,
    revision: i64,
    issued_at: i64,
    expires_at: i64,
    target: PolicyTarget,
    desktop: DesktopPolicy,
}

pub(crate) struct DeviceAuthState {
    pub api_server: String,
    pub rustdesk_id: String,
    pub device_id: i64,
}

fn identity_path() -> std::path::PathBuf {
    Config::path(IDENTITY_FILE)
}

fn load_identity() -> DesktopIdentity {
    load_path(identity_path())
}

fn store_identity(identity: &DesktopIdentity) -> ResultType<()> {
    store_path(identity_path(), identity)
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> ResultType<[u8; N]> {
    STANDARD
        .decode(value)
        .with_context(|| format!("Failed to decode desktop {label}"))?
        .try_into()
        .map_err(|_| anyhow!("Invalid desktop {label} length"))
}

fn validate_api_server(value: &str) -> ResultType<String> {
    let mut url = reqwest::Url::parse(value).context("Invalid desktop management API URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        bail!("Invalid desktop management API URL")
    }
    let loopback_http = url.scheme() == "http"
        && url
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .map(|address| address.is_loopback())
            .unwrap_or_else(|| url.host_str() == Some("localhost"));
    if url.scheme() != "https" && !loopback_http {
        bail!("Desktop management API requires HTTPS")
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn append_field(message: &mut Vec<u8>, value: &str) {
    message.extend_from_slice(value.as_bytes());
    message.push(0);
}

fn registration_message(
    version: u32,
    request_id: &str,
    token: &str,
    id: &str,
    uuid: &str,
    hostname: &str,
    os: &str,
    arch: &str,
    client_version: &str,
    sign_public_key: &[u8],
    box_public_key: &[u8],
    timestamp: i64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(256);
    message.extend_from_slice(b"RUD-DESKTOP-REGISTER\0");
    for value in [
        version.to_string(),
        request_id.to_owned(),
        id.to_owned(),
        uuid.to_owned(),
        hostname.to_owned(),
        os.to_owned(),
        arch.to_owned(),
        client_version.to_owned(),
    ] {
        append_field(&mut message, &value);
    }
    message.extend_from_slice(sign_public_key);
    message.push(0);
    message.extend_from_slice(box_public_key);
    message.push(0);
    append_field(&mut message, &timestamp.to_string());
    message.extend_from_slice(&sha256::hash(token.as_bytes()).0);
    message
}

fn policy_signature_message(envelope: &PolicyEnvelope, ciphertext: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(128 + ciphertext.len());
    message.extend_from_slice(b"RUD-DESKTOP-POLICY\0");
    message.extend_from_slice(&envelope.version.to_be_bytes());
    append_field(&mut message, &envelope.purpose);
    append_field(&mut message, &envelope.key_id);
    append_field(&mut message, &envelope.device_id.to_string());
    append_field(&mut message, &envelope.revision.to_string());
    message.extend_from_slice(ciphertext);
    message
}

pub fn enroll_from_file(api_server: &str, token_file: &Path) -> ResultType<()> {
    let metadata = std::fs::metadata(token_file).context("Failed to read enrollment token file")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_TOKEN_SIZE {
        bail!("Invalid enrollment token file")
    }
    let token = std::fs::read_to_string(token_file)
        .context("Failed to read enrollment token file")?
        .trim()
        .to_owned();
    enroll(api_server, &token)
}

fn normalize_enrollment_token(token: &str) -> ResultType<String> {
    let token = token.trim();
    if token.is_empty() || token.len() as u64 > MAX_TOKEN_SIZE {
        bail!("Invalid enrollment token")
    }
    Ok(token.to_owned())
}

pub fn enroll(api_server: &str, token: &str) -> ResultType<()> {
    let api_server = validate_api_server(api_server)?;
    let token = normalize_enrollment_token(token)?;
    let _guard = IDENTITY_LOCK
        .lock()
        .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
    let existing = load_identity();
    if existing.device_id > 0 {
        bail!("Desktop is already enrolled")
    }
    let id = Config::get_id();
    let uuid = crate::encode64(hbb_common::get_uuid());
    if id.is_empty() || uuid.is_empty() {
        bail!("RustDesk identity is not ready")
    }
    let sysinfo = crate::get_sysinfo();
    let hostname = sysinfo["hostname"].as_str().unwrap_or_default();
    let (
        sign_public_key,
        sign_secret_key,
        box_public_key,
        box_secret_key,
        request_id,
        mut timestamp,
    ) = if existing.enrollment_request_id.is_empty() {
        let (sign_public_key, sign_secret_key) = sign::gen_keypair();
        let (box_public_key, box_secret_key) = box_::gen_keypair();
        let request_id = STANDARD.encode(hbb_common::sodiumoxide::randombytes::randombytes(24));
        let timestamp = hbb_common::get_time() / 1000;
        store_identity(&DesktopIdentity {
            api_server: api_server.clone(),
            rustdesk_id: id.clone(),
            uuid: uuid.clone(),
            sign_public_key: STANDARD.encode(sign_public_key.0),
            sign_secret_key: STANDARD.encode(sign_secret_key.0),
            box_public_key: STANDARD.encode(box_public_key.0),
            box_secret_key: STANDARD.encode(box_secret_key.0),
            enrollment_request_id: request_id.clone(),
            enrollment_token: token.clone(),
            enrollment_timestamp: timestamp,
            ..Default::default()
        })?;
        (
            sign_public_key,
            sign_secret_key,
            box_public_key,
            box_secret_key,
            request_id,
            timestamp,
        )
    } else {
        if existing.api_server != api_server
            || existing.rustdesk_id != id
            || existing.uuid != uuid
            || existing.enrollment_token != token
            || existing.enrollment_timestamp <= 0
        {
            bail!("A different desktop enrollment is already pending")
        }
        let sign_public_key = sign::PublicKey(decode_fixed::<{ sign::PUBLICKEYBYTES }>(
            &existing.sign_public_key,
            "signing public key",
        )?);
        let sign_secret_key = sign::SecretKey::from_slice(
            &STANDARD
                .decode(&existing.sign_secret_key)
                .context("Invalid desktop signing key")?,
        )
        .ok_or_else(|| anyhow!("Invalid desktop signing key"))?;
        let box_public_key = box_::PublicKey(decode_fixed::<{ box_::PUBLICKEYBYTES }>(
            &existing.box_public_key,
            "box public key",
        )?);
        let box_secret_key = box_::SecretKey(decode_fixed::<{ box_::SECRETKEYBYTES }>(
            &existing.box_secret_key,
            "box secret key",
        )?);
        (
            sign_public_key,
            sign_secret_key,
            box_public_key,
            box_secret_key,
            existing.enrollment_request_id,
            existing.enrollment_timestamp,
        )
    };
    let client = if api_server.starts_with("https://") {
        crate::hbbs_http::create_http_client_with_url_strict(&api_server)?
    } else {
        crate::hbbs_http::create_http_client_with_url(&api_server)
    };
    for attempt in 0..2 {
        let message = registration_message(
            ENVELOPE_VERSION,
            &request_id,
            &token,
            &id,
            &uuid,
            hostname,
            std::env::consts::OS,
            std::env::consts::ARCH,
            crate::VERSION,
            &sign_public_key.0,
            &box_public_key.0,
            timestamp,
        );
        let signature = sign::sign_detached(&message, &sign_secret_key);
        let body = json!({
            "version": ENVELOPE_VERSION,
            "request_id": request_id,
            "token": token,
            "id": id,
            "uuid": uuid,
            "hostname": hostname,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "client_version": crate::VERSION,
            "sign_public_key": STANDARD.encode(sign_public_key.0),
            "box_public_key": STANDARD.encode(box_public_key.0),
            "timestamp": timestamp,
            "signature": STANDARD.encode(signature.to_bytes()),
        });
        let response = match client
            .post(format!("{api_server}/api/device/register/desktop"))
            .json(&body)
            .send()
        {
            Ok(response) => response,
            Err(error) if attempt == 0 => {
                hbb_common::log::warn!("Desktop enrollment request will be retried: {error}");
                continue;
            }
            Err(error) => return Err(error).context("Desktop enrollment request failed"),
        };
        let status = response.status();
        let bytes = response
            .bytes()
            .context("Failed to read enrollment response")?;
        let response: RegistrationResponse =
            serde_json::from_slice(&bytes).context("Invalid desktop enrollment response")?;
        if status.is_success()
            && response.accepted
            && response.device_id > 0
            && decode_fixed::<{ sign::PUBLICKEYBYTES }>(
                &response.policy_verify_public_key,
                "policy verification key",
            )
            .is_ok()
            && !response.policy_verify_key_id.is_empty()
        {
            let identity = DesktopIdentity {
                api_server,
                rustdesk_id: id,
                uuid,
                device_id: response.device_id,
                next_sequence: response.last_sequence.saturating_add(1).max(1),
                sign_public_key: STANDARD.encode(sign_public_key.0),
                sign_secret_key: STANDARD.encode(sign_secret_key.0),
                box_public_key: STANDARD.encode(box_public_key.0),
                box_secret_key: STANDARD.encode(box_secret_key.0),
                policy_verify_key_id: response.policy_verify_key_id,
                policy_verify_public_key: response.policy_verify_public_key,
                password_status: "unchanged".to_owned(),
                ..Default::default()
            };
            store_identity(&identity)?;
            return Ok(());
        }
        if attempt == 0 && response.server_time > 0 {
            timestamp = response.server_time;
            let mut pending = load_identity();
            pending.enrollment_timestamp = timestamp;
            store_identity(&pending)?;
            continue;
        }
        bail!("Desktop enrollment was rejected with HTTP {status}")
    }
    bail!("Desktop enrollment was rejected")
}

pub fn auth_state(id: &str) -> Option<DeviceAuthState> {
    let _guard = IDENTITY_LOCK.lock().ok()?;
    let identity = load_identity();
    if identity.device_id <= 0
        || identity.api_server.is_empty()
        || identity.rustdesk_id != id
        || identity.uuid != crate::encode64(hbb_common::get_uuid())
    {
        return None;
    }
    Some(DeviceAuthState {
        api_server: identity.api_server,
        rustdesk_id: identity.rustdesk_id,
        device_id: identity.device_id,
    })
}

pub fn api_server(id: &str) -> String {
    auth_state(id)
        .map(|state| state.api_server)
        .unwrap_or_default()
}

pub fn policy_revision() -> i64 {
    let Ok(_guard) = IDENTITY_LOCK.lock() else {
        return 0;
    };
    load_identity().policy_revision
}

pub fn password_status() -> Value {
    let Ok(_guard) = IDENTITY_LOCK.lock() else {
        return json!({
            "applied_revision": 0,
            "status": "failed",
            "permanent_password_set": false,
            "last_error": "desktop identity lock is poisoned",
        });
    };
    let identity = load_identity();
    json!({
        "applied_revision": identity.policy_revision,
        "status": identity.password_status,
        "permanent_password_set": identity.permanent_password_set,
        "last_error": identity.password_error,
    })
}

pub fn safe_status() -> Value {
    let Ok(_guard) = IDENTITY_LOCK.lock() else {
        return json!({"enrolled": false, "error": "desktop identity lock is poisoned"});
    };
    let identity = load_identity();
    json!({
        "enrolled": identity.device_id > 0,
        "pending": identity.device_id <= 0 && !identity.enrollment_request_id.is_empty(),
        "api_server": identity.api_server,
        "rustdesk_id": identity.rustdesk_id,
        "device_id": identity.device_id,
        "policy_verify_key_id": identity.policy_verify_key_id,
        "policy_revision": identity.policy_revision,
        "password_status": identity.password_status,
        "permanent_password_set": identity.permanent_password_set,
        "password_error": identity.password_error,
    })
}

pub fn cancel_pending_enrollment() -> ResultType<bool> {
    let _guard = IDENTITY_LOCK
        .lock()
        .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
    let identity = load_identity();
    if identity.device_id > 0 {
        bail!("Desktop is already enrolled")
    }
    if identity.enrollment_request_id.is_empty() {
        return Ok(false);
    }
    let path = identity_path();
    if path.exists() {
        std::fs::remove_file(path).context("Failed to clear pending desktop enrollment")?;
    }
    Ok(true)
}

fn device_request_message(device_id: i64, sequence: i64, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(b"RUD-DEVICE-REQUEST\0");
    for value in [device_id, sequence] {
        append_field(&mut message, &value.to_string());
    }
    message.extend_from_slice(&sha256::hash(payload).0);
    message
}

pub async fn signed_post(
    url: String,
    payload: String,
    state: &DeviceAuthState,
) -> ResultType<(u16, String)> {
    let (sequence, signature) = {
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        if identity.device_id != state.device_id
            || identity.rustdesk_id != state.rustdesk_id
            || identity.api_server != state.api_server
        {
            bail!("Desktop identity changed")
        }
        let secret_key = sign::SecretKey::from_slice(
            &STANDARD
                .decode(&identity.sign_secret_key)
                .context("Invalid desktop signing key")?,
        )
        .ok_or_else(|| anyhow!("Invalid desktop signing key"))?;
        let sequence = identity.next_sequence.max(1);
        identity.next_sequence = sequence.saturating_add(1);
        store_identity(&identity)?;
        let signature = sign::sign_detached(
            &device_request_message(identity.device_id, sequence, payload.as_bytes()),
            &secret_key,
        );
        (sequence, signature)
    };
    let body = json!({
        "device_id": state.device_id,
        "sequence": sequence,
        "payload": STANDARD.encode(payload.as_bytes()),
        "signature": STANDARD.encode(signature.to_bytes()),
    })
    .to_string();
    crate::post_request_with_status(url, body, "").await
}

fn decode_policy(encoded: &str, identity: &DesktopIdentity) -> ResultType<PolicyPayload> {
    if encoded.len() > MAX_ENVELOPE_SIZE * 2 {
        bail!("Desktop policy envelope is too large")
    }
    let envelope_bytes = STANDARD
        .decode(encoded)
        .context("Invalid desktop policy encoding")?;
    if envelope_bytes.is_empty() || envelope_bytes.len() > MAX_ENVELOPE_SIZE {
        bail!("Invalid desktop policy envelope size")
    }
    let envelope: PolicyEnvelope =
        serde_json::from_slice(&envelope_bytes).context("Invalid desktop policy envelope")?;
    if envelope.version != ENVELOPE_VERSION
        || envelope.purpose != "desktop-policy"
        || envelope.key_id != identity.policy_verify_key_id
        || envelope.device_id != identity.device_id
        || envelope.revision <= 0
    {
        bail!("Unsupported desktop policy envelope")
    }
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext)
        .context("Invalid desktop policy ciphertext")?;
    let signature_bytes =
        decode_fixed::<{ sign::SIGNATUREBYTES }>(&envelope.signature, "policy signature")?;
    let signature = sign::Signature::from_bytes(&signature_bytes)
        .map_err(|_| anyhow!("Invalid desktop policy signature"))?;
    let verify_key = sign::PublicKey(decode_fixed::<{ sign::PUBLICKEYBYTES }>(
        &identity.policy_verify_public_key,
        "policy verification key",
    )?);
    if !sign::verify_detached(
        &signature,
        &policy_signature_message(&envelope, &ciphertext),
        &verify_key,
    ) {
        bail!("Desktop policy signature mismatch")
    }
    let box_public_key = box_::PublicKey(decode_fixed::<{ box_::PUBLICKEYBYTES }>(
        &identity.box_public_key,
        "box public key",
    )?);
    let box_secret_key = box_::SecretKey(decode_fixed::<{ box_::SECRETKEYBYTES }>(
        &identity.box_secret_key,
        "box secret key",
    )?);
    let plaintext = sealedbox::open(&ciphertext, &box_public_key, &box_secret_key)
        .map_err(|_| anyhow!("Desktop policy decryption failed"))?;
    let payload: PolicyPayload =
        serde_json::from_slice(&plaintext).context("Invalid desktop policy payload")?;
    let now = hbb_common::get_time() / 1000;
    if payload.version != ENVELOPE_VERSION
        || payload.revision != envelope.revision
        || payload.issued_at > now + 300
        || payload.expires_at <= now
        || payload.expires_at <= payload.issued_at
        || payload.target.device_id != identity.device_id
        || payload.target.rustdesk_id != identity.rustdesk_id
        || payload.target.uuid != identity.uuid
        || payload.desktop.unattended.permanent_password.len() > MAX_PASSWORD_SIZE
    {
        bail!("Invalid desktop policy")
    }
    match payload.desktop.unattended.password_action.as_str() {
        "unchanged" if payload.desktop.unattended.permanent_password.is_empty() => {}
        "clear" if payload.desktop.unattended.permanent_password.is_empty() => {}
        "set" if !payload.desktop.unattended.permanent_password.is_empty() => {}
        _ => bail!("Invalid desktop password action"),
    }
    Ok(payload)
}

fn record_policy_failure(error: &str) {
    let Ok(_guard) = IDENTITY_LOCK.lock() else {
        return;
    };
    let mut identity = load_identity();
    identity.password_status = "failed".to_owned();
    identity.password_error = error.chars().take(MAX_PASSWORD_SIZE).collect();
    if let Err(store_error) = store_identity(&identity) {
        hbb_common::log::warn!("Failed to store desktop policy error: {store_error}");
    }
}

pub async fn apply_policy(encoded: &str, id: &str, uuid: &str) -> ResultType<i64> {
    let decoded = {
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let identity = load_identity();
        if identity.rustdesk_id != id || identity.uuid != uuid {
            Err(anyhow!("Desktop policy target changed"))
        } else {
            decode_policy(encoded, &identity).map(|payload| (payload, identity.policy_revision))
        }
    };
    let (payload, current_revision) = match decoded {
        Ok(decoded) => decoded,
        Err(error) => {
            record_policy_failure(&error.to_string());
            return Err(error);
        }
    };
    if payload.revision < current_revision {
        let error = "Desktop policy revision rollback";
        record_policy_failure(error);
        bail!(error)
    };
    if payload.revision == current_revision {
        return Ok(current_revision);
    }
    let action = payload.desktop.unattended.password_action.clone();
    if action == "unchanged" {
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        identity.policy_revision = payload.revision;
        identity.password_status = "unchanged".to_owned();
        identity.password_error.clear();
        store_identity(&identity)?;
        return Ok(payload.revision);
    }
    {
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        identity.password_status = "applying".to_owned();
        identity.password_error.clear();
        store_identity(&identity)?;
    }
    let password = payload.desktop.unattended.permanent_password;
    let applied = match hbb_common::tokio::task::spawn_blocking(move || {
        crate::ui_interface::set_permanent_password_with_result(password)
    })
    .await
    {
        Ok(applied) => applied,
        Err(error) => {
            let error = format!("Desktop password task failed: {error}");
            record_policy_failure(&error);
            bail!(error)
        }
    };
    if !applied {
        let error = "Desktop service rejected permanent password update";
        record_policy_failure(error);
        bail!(error)
    }
    let _guard = IDENTITY_LOCK
        .lock()
        .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
    let mut identity = load_identity();
    identity.policy_revision = payload.revision;
    identity.password_status = if action == "clear" {
        "cleared".to_owned()
    } else {
        "success".to_owned()
    };
    identity.permanent_password_set = action == "set";
    identity.password_error.clear();
    store_identity(&identity)?;
    Ok(payload.revision)
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_enrollment_token, policy_signature_message, registration_message, PolicyEnvelope,
        MAX_TOKEN_SIZE,
    };
    use sha2::Digest;

    #[test]
    fn desktop_registration_message_is_stable() {
        let message = registration_message(
            1,
            "request",
            "rud1.selector.secret",
            "123",
            "uuid",
            "host",
            "linux",
            "x86_64",
            "1.4.6",
            &[1; 32],
            &[2; 32],
            1_700_000_000,
        );
        assert_eq!(
            hex::encode(sha2::Sha256::digest(message)),
            "d65d539941331f2eededeb5c0daf5da1ce3f0ab2bb7ebb4fc8573dbaf0946728"
        );
    }

    #[test]
    fn desktop_policy_signature_binds_target_and_revision() {
        let envelope = PolicyEnvelope {
            version: 1,
            purpose: "desktop-policy".to_owned(),
            key_id: "desktop-v1".to_owned(),
            device_id: 7,
            revision: 9,
            ciphertext: String::new(),
            signature: String::new(),
        };
        let first = policy_signature_message(&envelope, &[3; 48]);
        let mut changed = envelope;
        changed.revision += 1;
        assert_ne!(first, policy_signature_message(&changed, &[3; 48]));
    }

    #[test]
    fn desktop_enrollment_token_is_trimmed_and_bounded() {
        assert_eq!(
            normalize_enrollment_token("  rud1.selector.secret\n").unwrap(),
            "rud1.selector.secret"
        );
        assert!(normalize_enrollment_token("  ").is_err());
        assert!(normalize_enrollment_token(&"x".repeat(MAX_TOKEN_SIZE as usize + 1)).is_err());
    }
}
