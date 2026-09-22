use hbb_common::{
    anyhow::{anyhow, bail, Context},
    base64::{engine::general_purpose::STANDARD, Engine as _},
    config::{load_path, store_path, Config},
    sodiumoxide::crypto::{box_, hash::sha256, sealedbox, sign},
    ResultType,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, convert::TryInto, path::Path};

const IDENTITY_FILE: &str = "desktop_management.toml";
const ENVELOPE_VERSION: u32 = 1;
const MAX_TOKEN_SIZE: u64 = 4096;
const MAX_ENVELOPE_SIZE: usize = 256 * 1024;
const MAX_PASSWORD_SIZE: usize = 255;
const MAX_SERVER_FIELD_SIZE: usize = 255;
const PROFILE_CONNECT_TIMEOUT_SECONDS: u64 = 30;

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
    management_enabled: Option<bool>,
    next_sequence: i64,
    sign_public_key: String,
    sign_secret_key: String,
    box_public_key: String,
    box_secret_key: String,
    policy_verify_key_id: String,
    policy_verify_public_key: String,
    policy_revision: i64,
    password_revision: i64,
    password_status: String,
    permanent_password_set: bool,
    password_error: String,
    profile_received_revision: i64,
    profile_applied_revision: i64,
    profile_failed_revision: i64,
    profile_apply_status: String,
    profile_active_source: String,
    profile_error: String,
    profile_attempt_count: u64,
    profile_last_attempt_at: i64,
    profile_fingerprint: String,
    profile_candidate_envelope: String,
    profile_confirmed_enabled: bool,
    profile_confirmed_id_server: String,
    profile_confirmed_relay_server: String,
    profile_confirmed_key: String,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerProfilePolicy {
    enabled: bool,
    id_server: String,
    relay_server: String,
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopPolicy {
    unattended: UnattendedPolicy,
    server_profile: ServerProfilePolicy,
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

fn identity_management_enabled(identity: &DesktopIdentity) -> bool {
    identity.device_id > 0 && identity.management_enabled.unwrap_or(true)
}

pub fn is_management_enabled() -> bool {
    let Ok(_guard) = IDENTITY_LOCK.lock() else {
        return false;
    };
    identity_management_enabled(&load_identity())
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> ResultType<[u8; N]> {
    STANDARD
        .decode(value)
        .with_context(|| format!("Failed to decode desktop {label}"))?
        .try_into()
        .map_err(|_| anyhow!("Invalid desktop {label} length"))
}

fn valid_server_field(value: &str, required: bool) -> bool {
    (!required || !value.is_empty())
        && value.len() <= MAX_SERVER_FIELD_SIZE
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

fn validate_server_profile(profile: &ServerProfilePolicy) -> ResultType<()> {
    if !profile.enabled {
        if profile.id_server.is_empty() && profile.relay_server.is_empty() && profile.key.is_empty()
        {
            return Ok(());
        }
        bail!("profile_invalid")
    }
    if !valid_server_field(&profile.id_server, true)
        || !valid_server_field(&profile.relay_server, false)
        || !valid_server_field(&profile.key, false)
    {
        bail!("profile_invalid")
    }
    Ok(())
}

fn server_profile_options(profile: &ServerProfilePolicy) -> HashMap<String, String> {
    HashMap::from([
        (
            hbb_common::config::keys::OPTION_CUSTOM_RENDEZVOUS_SERVER.to_owned(),
            profile.id_server.clone(),
        ),
        (
            hbb_common::config::keys::OPTION_RELAY_SERVER.to_owned(),
            profile.relay_server.clone(),
        ),
        (
            hbb_common::config::keys::OPTION_KEY.to_owned(),
            profile.key.clone(),
        ),
    ])
}

fn server_profile_fingerprint(profile: &ServerProfilePolicy) -> String {
    let mut value = Vec::with_capacity(
        profile.id_server.len() + profile.relay_server.len() + profile.key.len() + 3,
    );
    for field in [&profile.id_server, &profile.relay_server, &profile.key] {
        append_field(&mut value, field);
    }
    hex::encode(&sha256::hash(&value).0[..16])
}

fn manual_fallback_source() -> String {
    if Config::is_manual_server_profile() {
        "manual_fallback".to_owned()
    } else {
        "none".to_owned()
    }
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

pub fn enroll_from_file(token_file: &Path) -> ResultType<()> {
    let metadata = std::fs::metadata(token_file).context("Failed to read enrollment token file")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_TOKEN_SIZE {
        bail!("Invalid enrollment token file")
    }
    let token = std::fs::read_to_string(token_file)
        .context("Failed to read enrollment token file")?
        .trim()
        .to_owned();
    enroll(&token)
}

fn normalize_enrollment_token(token: &str) -> ResultType<String> {
    let token = token.trim();
    if token.is_empty() || token.len() as u64 > MAX_TOKEN_SIZE {
        bail!("Invalid enrollment token")
    }
    Ok(token.to_owned())
}

pub fn enroll(token: &str) -> ResultType<()> {
    let token = normalize_enrollment_token(token)?;
    let api_server = crate::desktop_enrollment_token::api_server(&token)?;
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
            let password_cleared =
                crate::ui_interface::set_managed_permanent_password_with_result(String::new());
            let identity = DesktopIdentity {
                api_server,
                rustdesk_id: id,
                uuid,
                device_id: response.device_id,
                management_enabled: Some(password_cleared),
                next_sequence: response.last_sequence.saturating_add(1).max(1),
                sign_public_key: STANDARD.encode(sign_public_key.0),
                sign_secret_key: STANDARD.encode(sign_secret_key.0),
                box_public_key: STANDARD.encode(box_public_key.0),
                box_secret_key: STANDARD.encode(box_secret_key.0),
                policy_verify_key_id: response.policy_verify_key_id,
                policy_verify_public_key: response.policy_verify_public_key,
                password_status: if password_cleared {
                    "cleared"
                } else {
                    "failed"
                }
                .to_owned(),
                password_error: if password_cleared {
                    String::new()
                } else {
                    "Desktop service rejected permanent password cleanup".to_owned()
                },
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
    if !identity_management_enabled(&identity)
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
    let applied_revision = if identity.password_revision > 0 {
        identity.password_revision
    } else {
        identity.policy_revision
    };
    json!({
        "applied_revision": applied_revision,
        "status": identity.password_status,
        "permanent_password_set": identity.permanent_password_set,
        "last_error": identity.password_error,
    })
}

pub fn server_profile_status() -> Value {
    let Ok(_guard) = IDENTITY_LOCK.lock() else {
        return json!({
            "received_revision": 0,
            "applied_revision": 0,
            "failed_revision": 0,
            "apply_status": "failed",
            "active_source": "none",
            "connected": false,
            "fingerprint": "",
            "last_error": "desktop identity lock is poisoned",
        });
    };
    let identity = load_identity();
    json!({
        "policy_revision": identity.profile_applied_revision,
        "received_revision": identity.profile_received_revision,
        "applied_revision": identity.profile_applied_revision,
        "failed_revision": identity.profile_failed_revision,
        "apply_status": identity.profile_apply_status,
        "active_source": identity.profile_active_source,
        "connected": hbb_common::config::get_online_state() > 0,
        "fingerprint": identity.profile_fingerprint,
        "last_error": identity.profile_error,
    })
}

pub fn safe_status() -> Value {
    let Ok(_guard) = IDENTITY_LOCK.lock() else {
        return json!({"enrolled": false, "error": "desktop identity lock is poisoned"});
    };
    let identity = load_identity();
    json!({
        "enrolled": identity.device_id > 0,
        "enabled": identity_management_enabled(&identity),
        "pending": identity.device_id <= 0 && !identity.enrollment_request_id.is_empty(),
        "api_server": identity.api_server,
        "rustdesk_id": identity.rustdesk_id,
        "device_id": identity.device_id,
        "policy_verify_key_id": identity.policy_verify_key_id,
        "policy_revision": identity.policy_revision,
        "received_revision": identity.profile_received_revision,
        "applied_revision": identity.profile_applied_revision,
        "failed_revision": identity.profile_failed_revision,
        "profile_apply_status": identity.profile_apply_status,
        "profile_active_source": identity.profile_active_source,
        "profile_connected": hbb_common::config::get_online_state() > 0,
        "profile_error": identity.profile_error,
        "password_status": identity.password_status,
        "permanent_password_set": identity.permanent_password_set,
        "password_error": identity.password_error,
    })
}

pub fn set_management_enabled(enabled: bool) -> ResultType<bool> {
    let device_id = {
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        if identity.device_id <= 0 {
            bail!("Desktop is not enrolled")
        }
        if identity_management_enabled(&identity) == enabled {
            return Ok(false);
        }
        if !enabled {
            identity.management_enabled = Some(false);
            store_identity(&identity)?;
        }
        identity.device_id
    };

    if !crate::ui_interface::set_managed_permanent_password_with_result(String::new()) {
        if !enabled {
            let _guard = IDENTITY_LOCK
                .lock()
                .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
            let mut identity = load_identity();
            if identity.device_id == device_id {
                identity.management_enabled = Some(true);
                store_identity(&identity)?;
            }
        }
        bail!("Desktop service rejected permanent password cleanup")
    }

    if !enabled && Config::clear_desktop_managed_server_profile() {
        crate::rendezvous_mediator::RendezvousMediator::restart_for_managed_profile();
    }

    let _guard = IDENTITY_LOCK
        .lock()
        .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
    let mut identity = load_identity();
    if identity.device_id != device_id {
        bail!("Desktop identity changed")
    }
    identity.management_enabled = Some(enabled);
    identity.policy_revision = 0;
    identity.password_revision = 0;
    identity.password_status = if enabled { "pending" } else { "cleared" }.to_owned();
    identity.permanent_password_set = false;
    identity.password_error.clear();
    identity.profile_received_revision = 0;
    identity.profile_applied_revision = 0;
    identity.profile_failed_revision = 0;
    identity.profile_apply_status = if enabled { "idle" } else { "disabled" }.to_owned();
    identity.profile_active_source = if enabled {
        "none".to_owned()
    } else {
        manual_fallback_source()
    };
    identity.profile_error.clear();
    identity.profile_candidate_envelope.clear();
    store_identity(&identity)?;
    Ok(true)
}

pub fn retry_failed_server_profile() -> ResultType<bool> {
    let _guard = IDENTITY_LOCK
        .lock()
        .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
    let mut identity = load_identity();
    if identity.device_id <= 0 || identity.profile_failed_revision <= 0 {
        return Ok(false);
    }
    identity.policy_revision = identity.profile_failed_revision.saturating_sub(1);
    identity.profile_failed_revision = 0;
    identity.profile_apply_status = "idle".to_owned();
    identity.profile_error.clear();
    store_identity(&identity)?;
    Ok(true)
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
        if !identity_management_enabled(&identity)
            || identity.device_id != state.device_id
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
    validate_server_profile(&payload.desktop.server_profile)?;
    Ok(payload)
}

pub fn restore_confirmed_server_profile() {
    let Ok(_guard) = IDENTITY_LOCK.lock() else {
        return;
    };
    let identity = load_identity();
    if !identity_management_enabled(&identity)
        || !identity.profile_confirmed_enabled
        || identity.profile_applied_revision <= 0
    {
        return;
    }
    let profile = ServerProfilePolicy {
        enabled: true,
        id_server: identity.profile_confirmed_id_server,
        relay_server: identity.profile_confirmed_relay_server,
        key: identity.profile_confirmed_key,
    };
    if let Err(error) = validate_server_profile(&profile) {
        hbb_common::log::warn!("Failed to restore desktop managed profile: {error}");
        return;
    }
    Config::set_desktop_managed_server_profile(server_profile_options(&profile));
}

fn restore_previous_server_profile(identity: &DesktopIdentity) {
    if identity.profile_confirmed_enabled {
        let previous = ServerProfilePolicy {
            enabled: true,
            id_server: identity.profile_confirmed_id_server.clone(),
            relay_server: identity.profile_confirmed_relay_server.clone(),
            key: identity.profile_confirmed_key.clone(),
        };
        Config::set_desktop_managed_server_profile(server_profile_options(&previous));
    } else {
        Config::clear_desktop_managed_server_profile();
    }
    crate::rendezvous_mediator::RendezvousMediator::restart_for_managed_profile();
}

async fn apply_server_profile(
    profile: &ServerProfilePolicy,
    revision: i64,
    encoded: &str,
) -> ResultType<()> {
    if !is_management_enabled() {
        bail!("Desktop management is disabled")
    }
    let previous = {
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        identity.profile_received_revision = revision;
        identity.profile_apply_status = "applying".to_owned();
        identity.profile_error.clear();
        identity.profile_attempt_count = identity.profile_attempt_count.saturating_add(1);
        identity.profile_last_attempt_at = hbb_common::get_time() / 1000;
        identity.profile_candidate_envelope = encoded.to_owned();
        store_identity(&identity)?;
        identity
    };

    if !profile.enabled {
        if Config::clear_desktop_managed_server_profile() {
            crate::rendezvous_mediator::RendezvousMediator::restart_for_managed_profile();
        }
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        identity.profile_applied_revision = revision;
        identity.profile_failed_revision = 0;
        identity.profile_apply_status = "disabled".to_owned();
        identity.profile_active_source = manual_fallback_source();
        identity.profile_error.clear();
        identity.profile_fingerprint.clear();
        identity.profile_candidate_envelope.clear();
        identity.profile_confirmed_enabled = false;
        identity.profile_confirmed_id_server.clear();
        identity.profile_confirmed_relay_server.clear();
        identity.profile_confirmed_key.clear();
        store_identity(&identity)?;
        return Ok(());
    }

    let unchanged = previous.profile_confirmed_enabled
        && previous.profile_confirmed_id_server == profile.id_server
        && previous.profile_confirmed_relay_server == profile.relay_server
        && previous.profile_confirmed_key == profile.key
        && Config::desktop_managed_server_profile_active();
    if unchanged {
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        identity.profile_applied_revision = revision;
        identity.profile_failed_revision = 0;
        identity.profile_apply_status = "success".to_owned();
        identity.profile_active_source = "managed".to_owned();
        identity.profile_error.clear();
        identity.profile_fingerprint = server_profile_fingerprint(profile);
        identity.profile_candidate_envelope.clear();
        store_identity(&identity)?;
        return Ok(());
    }

    Config::set_desktop_managed_server_profile(server_profile_options(profile));
    let generation = crate::rendezvous_mediator::RendezvousMediator::restart_for_managed_profile();
    let deadline = hbb_common::tokio::time::Instant::now()
        + std::time::Duration::from_secs(PROFILE_CONNECT_TIMEOUT_SECONDS);
    let connected = loop {
        if crate::rendezvous_mediator::RendezvousMediator::managed_profile_is_online(generation)
            && hbb_common::config::get_online_state() > 0
        {
            break true;
        }
        if hbb_common::tokio::time::Instant::now() >= deadline {
            break false;
        }
        hbb_common::tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    };

    if !is_management_enabled() {
        if Config::clear_desktop_managed_server_profile() {
            crate::rendezvous_mediator::RendezvousMediator::restart_for_managed_profile();
        }
        bail!("Desktop management is disabled")
    }

    if connected {
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        identity.profile_applied_revision = revision;
        identity.profile_failed_revision = 0;
        identity.profile_apply_status = "success".to_owned();
        identity.profile_active_source = "managed".to_owned();
        identity.profile_error.clear();
        identity.profile_fingerprint = server_profile_fingerprint(profile);
        identity.profile_candidate_envelope.clear();
        identity.profile_confirmed_enabled = true;
        identity.profile_confirmed_id_server = profile.id_server.clone();
        identity.profile_confirmed_relay_server = profile.relay_server.clone();
        identity.profile_confirmed_key = profile.key.clone();
        store_identity(&identity)?;
        return Ok(());
    }

    restore_previous_server_profile(&previous);
    let _guard = IDENTITY_LOCK
        .lock()
        .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
    let mut identity = load_identity();
    identity.profile_failed_revision = revision;
    identity.profile_apply_status = "rolled_back".to_owned();
    identity.profile_active_source = if previous.profile_confirmed_enabled {
        "managed".to_owned()
    } else {
        manual_fallback_source()
    };
    identity.profile_error = "profile_connect_timeout".to_owned();
    store_identity(&identity)?;
    Ok(())
}

fn record_policy_failure(error: &str) {
    let Ok(_guard) = IDENTITY_LOCK.lock() else {
        return;
    };
    let mut identity = load_identity();
    if error.starts_with("profile_") {
        identity.profile_apply_status = "failed".to_owned();
        identity.profile_error = error.chars().take(MAX_PASSWORD_SIZE).collect();
    } else {
        identity.password_status = "failed".to_owned();
        identity.password_error = error.chars().take(MAX_PASSWORD_SIZE).collect();
    }
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
        if !identity_management_enabled(&identity) {
            Err(anyhow!("Desktop management is disabled"))
        } else if identity.rustdesk_id != id || identity.uuid != uuid {
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
    {
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        identity.profile_received_revision = payload.revision;
        store_identity(&identity)?;
    }
    let action = payload.desktop.unattended.password_action.clone();
    if action == "unchanged" {
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        identity.password_revision = payload.revision;
        identity.password_status = "unchanged".to_owned();
        identity.password_error.clear();
        store_identity(&identity)?;
    } else {
        {
            let _guard = IDENTITY_LOCK
                .lock()
                .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
            let mut identity = load_identity();
            identity.password_status = "applying".to_owned();
            identity.password_error.clear();
            store_identity(&identity)?;
        }
        let password = payload.desktop.unattended.permanent_password.clone();
        let applied = match hbb_common::tokio::task::spawn_blocking(move || {
            crate::ui_interface::set_managed_permanent_password_with_result(password)
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
        if !is_management_enabled() {
            let _ = crate::ui_interface::set_managed_permanent_password_with_result(String::new());
            bail!("Desktop management is disabled")
        }
        let _guard = IDENTITY_LOCK
            .lock()
            .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
        let mut identity = load_identity();
        identity.password_revision = payload.revision;
        identity.password_status = if action == "clear" {
            "cleared".to_owned()
        } else {
            "success".to_owned()
        };
        identity.permanent_password_set = action == "set";
        identity.password_error.clear();
        store_identity(&identity)?;
    }

    apply_server_profile(&payload.desktop.server_profile, payload.revision, encoded).await?;
    let _guard = IDENTITY_LOCK
        .lock()
        .map_err(|_| anyhow!("Desktop identity lock is poisoned"))?;
    let mut identity = load_identity();
    identity.policy_revision = payload.revision;
    store_identity(&identity)?;
    Ok(payload.revision)
}

#[cfg(test)]
mod tests {
    use super::{
        identity_management_enabled, normalize_enrollment_token, policy_signature_message,
        registration_message, server_profile_fingerprint, validate_server_profile, DesktopIdentity,
        PolicyEnvelope, ServerProfilePolicy, MAX_TOKEN_SIZE,
    };
    use sha2::Digest;

    #[test]
    fn desktop_registration_message_is_stable() {
        let message = registration_message(
            1,
            "request",
            "rud2.selector.secret.nonce.ciphertext",
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
            "11e63c27568fd2b46a2df81243e503a0ea320fec406c5ab15d4b1b25583fde2e"
        );
    }

    #[test]
    fn enrolled_identity_defaults_to_management_enabled_for_migration() {
        let mut identity = DesktopIdentity {
            device_id: 7,
            ..Default::default()
        };
        assert!(identity_management_enabled(&identity));

        identity.management_enabled = Some(false);
        assert!(!identity_management_enabled(&identity));
        identity.management_enabled = Some(true);
        assert!(identity_management_enabled(&identity));

        identity.device_id = 0;
        assert!(!identity_management_enabled(&identity));
    }

    #[test]
    fn desktop_server_profile_validation_rejects_unsafe_fields() {
        let valid = ServerProfilePolicy {
            enabled: true,
            id_server: "id.example.com:21116".to_owned(),
            relay_server: "relay.example.com:21117".to_owned(),
            key: "server-key".to_owned(),
        };
        assert!(validate_server_profile(&valid).is_ok());
        assert_eq!(server_profile_fingerprint(&valid).len(), 32);

        let mut invalid = valid.clone();
        invalid.id_server = "id.example.com bad".to_owned();
        assert!(validate_server_profile(&invalid).is_err());

        let invalid_disabled = ServerProfilePolicy {
            enabled: false,
            id_server: "id.example.com".to_owned(),
            relay_server: String::new(),
            key: String::new(),
        };
        assert!(validate_server_profile(&invalid_disabled).is_err());
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
            normalize_enrollment_token("  rud2.selector.secret.nonce.ciphertext\n").unwrap(),
            "rud2.selector.secret.nonce.ciphertext"
        );
        assert!(normalize_enrollment_token("  ").is_err());
        assert!(normalize_enrollment_token(&"x".repeat(MAX_TOKEN_SIZE as usize + 1)).is_err());
    }

    #[test]
    fn desktop_enrollment_token_supplies_api_server() {
        let token = "rud2.IKpRWaNJajsA_TyS.r5LPh4PbO6qOmg2BaMTR6eHDW9PePFGDvGaac8RR4bc.KkgP5kRqdsqT09eqIbIlM-uj8FufgWQD.wqZfN0L5dqGYaK9kFcNvjL7uYI8Ix_mwu2SWKab4TkKyzPWLDms1JdtBldhvlBjtGQY";
        assert_eq!(
            crate::desktop_enrollment_token::api_server(&token).unwrap(),
            "https://api.example.com/management"
        );
        assert!(crate::desktop_enrollment_token::api_server("rud1.selector.secret").is_err());
    }
}
