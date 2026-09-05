use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(not(any(target_os = "ios")))]
use crate::{ui_interface::get_builtin_option, Connection};
use hbb_common::{
    config::{self, keys, Config, LocalConfig},
    log,
    tokio::{self, sync::broadcast, time::Instant},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const TIME_HEARTBEAT: Duration = Duration::from_secs(15);
const UPLOAD_SYSINFO_TIMEOUT: Duration = Duration::from_secs(120);
const TIME_CONN: Duration = Duration::from_secs(3);

#[cfg(target_os = "android")]
const DEVICE_ID_OPTION: &str = "android-provisioning-device-id";
#[cfg(target_os = "android")]
const DEVICE_SEQUENCE_OPTION: &str = "android-provisioning-device-sequence";
#[cfg(target_os = "android")]
const DEVICE_API_HASH_OPTION: &str = "android-provisioning-device-api-hash";

#[cfg(not(any(target_os = "ios")))]
lazy_static::lazy_static! {
    static ref SENDER : Mutex<broadcast::Sender<Vec<i32>>> = Mutex::new(start_hbbs_sync());
    static ref PRO: Arc<Mutex<bool>> = Default::default();
}

#[cfg(not(any(target_os = "ios")))]
pub fn start() {
    let _sender = SENDER.lock().unwrap();
}

#[cfg(not(target_os = "ios"))]
pub fn signal_receiver() -> broadcast::Receiver<Vec<i32>> {
    SENDER.lock().unwrap().subscribe()
}

#[cfg(not(any(target_os = "ios")))]
fn start_hbbs_sync() -> broadcast::Sender<Vec<i32>> {
    let (tx, _rx) = broadcast::channel::<Vec<i32>>(16);
    std::thread::spawn(move || start_hbbs_sync_async());
    return tx;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StrategyOptions {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config_options: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, String>,
}

struct InfoUploaded {
    uploaded: bool,
    url: String,
    last_uploaded: Option<Instant>,
    id: String,
    username: Option<String>,
}

impl Default for InfoUploaded {
    fn default() -> Self {
        Self {
            uploaded: false,
            url: "".to_owned(),
            last_uploaded: None,
            id: "".to_owned(),
            username: None,
        }
    }
}

impl InfoUploaded {
    fn uploaded(url: String, id: String, username: String) -> Self {
        Self {
            uploaded: true,
            url,
            last_uploaded: None,
            id,
            username: Some(username),
        }
    }
}

#[cfg(not(any(target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn start_hbbs_sync_async() {
    let mut interval = crate::rustdesk_interval(tokio::time::interval_at(
        Instant::now() + TIME_CONN,
        TIME_CONN,
    ));
    let mut last_sent: Option<Instant> = None;
    let mut info_uploaded = InfoUploaded::default();
    let mut sysinfo_ver = "".to_owned();
    #[cfg(target_os = "android")]
    let mut device_auth: Option<DeviceAuthState> = None;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let (url, requires_device_auth) = heartbeat_target().await;
                let id = Config::get_id();
                if url.is_empty() {
                    *PRO.lock().unwrap() = false;
                    continue;
                }
                if config::option2bool("stop-service", &Config::get_option("stop-service")) {
                    continue;
                }
                #[cfg(target_os = "android")]
                if requires_device_auth {
                    let api_server = url.trim_end_matches("/api/device/heartbeat");
                    let needs_registration = device_auth
                        .as_ref()
                        .map(|state| state.api_server != api_server || state.rustdesk_id != id)
                        .unwrap_or(true);
                    if needs_registration {
                        device_auth = register_device(api_server, &id).await;
                    }
                    if device_auth.is_none() {
                        *PRO.lock().unwrap() = false;
                        continue;
                    }
                }
                let conns = Connection::alive_conns();
                if info_uploaded.uploaded && (url != info_uploaded.url || id != info_uploaded.id) {
                    info_uploaded.uploaded = false;
                    *PRO.lock().unwrap() = false;
                }
                // For Windows:
                // We can't skip uploading sysinfo when the username is empty, because the username may
                // always be empty before login. We also need to upload the other sysinfo info.
                //
                // https://github.com/rustdesk/rustdesk/discussions/8031
                // We still need to check the username after uploading sysinfo, because
                // 1. The username may be empty when logining in, and it can be fetched after a while.
                //    In this case, we need to upload sysinfo again.
                // 2. The username may be changed after uploading sysinfo, and we need to upload sysinfo again.
                //
                // The Windows session will switch to the last user session before the restart,
                // so it may be able to get the username before login.
                // But strangely, sometimes we can get the username before login,
                // we may not be able to get the username before login after the next restart.
                let mut v = crate::get_sysinfo();
                let sys_username = v["username"].as_str().unwrap_or_default().to_string();
                // Though the username comparison is only necessary on Windows,
                // we still keep the comparison on other platforms for consistency.
                let need_upload = (!info_uploaded.uploaded || info_uploaded.username.as_ref() != Some(&sys_username)) &&
                    info_uploaded.last_uploaded.map(|x| x.elapsed() >= UPLOAD_SYSINFO_TIMEOUT).unwrap_or(true);
                if need_upload {
                    v["version"] = json!(crate::VERSION);
                    v["id"] = json!(id);
                    v["uuid"] = json!(crate::encode64(hbb_common::get_uuid()));
                    let ab_name = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_NAME);
                    if !ab_name.is_empty() {
                        v[keys::OPTION_PRESET_ADDRESS_BOOK_NAME] = json!(ab_name);
                    }
                    let ab_tag = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_TAG);
                    if !ab_tag.is_empty() {
                        v[keys::OPTION_PRESET_ADDRESS_BOOK_TAG] = json!(ab_tag);
                    }
                    let ab_alias = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_ALIAS);
                    if !ab_alias.is_empty() {
                        v[keys::OPTION_PRESET_ADDRESS_BOOK_ALIAS] = json!(ab_alias);
                    }
                    let ab_password = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_PASSWORD);
                    if !ab_password.is_empty() {
                        v[keys::OPTION_PRESET_ADDRESS_BOOK_PASSWORD] = json!(ab_password);
                    }
                    let ab_note = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_NOTE);
                    if !ab_note.is_empty() {
                        v[keys::OPTION_PRESET_ADDRESS_BOOK_NOTE] = json!(ab_note);
                    }
                    let username = get_builtin_option(keys::OPTION_PRESET_USERNAME);
                    if !username.is_empty() {
                        v[keys::OPTION_PRESET_USERNAME] = json!(username);
                    }
                    let strategy_name = get_builtin_option(keys::OPTION_PRESET_STRATEGY_NAME);
                    if !strategy_name.is_empty() {
                        v[keys::OPTION_PRESET_STRATEGY_NAME] = json!(strategy_name);
                    }
                    let device_group_name = get_builtin_option(keys::OPTION_PRESET_DEVICE_GROUP_NAME);
                    if !device_group_name.is_empty() {
                        v[keys::OPTION_PRESET_DEVICE_GROUP_NAME] = json!(device_group_name);
                    }
                    let device_username = Config::get_option(keys::OPTION_PRESET_DEVICE_USERNAME);
                    if !device_username.is_empty() {
                        v["username"] = json!(device_username);
                    }
                    let device_name = Config::get_option(keys::OPTION_PRESET_DEVICE_NAME);
                    if !device_name.is_empty() {
                        v["hostname"] = json!(device_name);
                    }
                    let note = Config::get_option(keys::OPTION_PRESET_NOTE);
                    if !note.is_empty() {
                        v[keys::OPTION_PRESET_NOTE] = json!(note);
                    }
                    let v = v.to_string();
                    let mut hash = "".to_owned();
                    if crate::is_public(&url) {
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(url.as_bytes());
                        hasher.update(&v.as_bytes());
                        let res = hasher.finalize();
                        hash = hbb_common::base64::encode(&res[..]);
                        let old_hash = config::Status::get("sysinfo_hash");
                        let ver = config::Status::get("sysinfo_ver"); // sysinfo_ver is the version of sysinfo on server's side
                        if hash == old_hash {
                            // When the api doesn't exist, Ok("") will be returned in test.
                            let samever = match crate::post_request(url.replace("heartbeat", "sysinfo_ver"), "".to_owned(), "").await {
                                Ok(x)  => {
                                    sysinfo_ver = x.clone();
                                    *PRO.lock().unwrap() = true;
                                    x == ver
                                }
                                _ => {
                                    false // to make sure Pro can be assigned in below post for old
                                            // hbbs pro not supporting sysinfo_ver, use false for ensuring
                                }
                            };
                            if samever {
                                info_uploaded = InfoUploaded::uploaded(url.clone(), id.clone(), sys_username);
                                log::info!("sysinfo not changed, skip upload");
                                continue;
                            }
                        }
                    }
                    #[cfg(target_os = "android")]
                    let sysinfo_response = if requires_device_auth {
                        let Some(state) = device_auth.as_mut() else {
                            continue;
                        };
                        signed_device_post(
                            url.replace("heartbeat", "sysinfo"),
                            v,
                            state,
                        )
                        .await
                        .map(|(_, body)| body)
                    } else {
                        crate::post_request(url.replace("heartbeat", "sysinfo"), v, "").await
                    };
                    #[cfg(not(target_os = "android"))]
                    let sysinfo_response = crate::post_request(url.replace("heartbeat", "sysinfo"), v, "").await;
                    match sysinfo_response {
                        Ok(x)  => {
                            if x == "SYSINFO_UPDATED" {
                                info_uploaded = InfoUploaded::uploaded(url.clone(), id.clone(), sys_username);
                                log::info!("sysinfo updated");
                                if !hash.is_empty() {
                                    config::Status::set("sysinfo_hash", hash);
                                    config::Status::set("sysinfo_ver", sysinfo_ver.clone());
                                }
                                *PRO.lock().unwrap() = true;
                            } else if x == "ID_NOT_FOUND" {
                                info_uploaded.last_uploaded = None; // next heartbeat will upload sysinfo again
                            } else {
                                info_uploaded.last_uploaded = Some(Instant::now());
                            }
                        }
                        _ => {
                            info_uploaded.last_uploaded = Some(Instant::now());
                        }
                    }
                }
                if conns.is_empty() && last_sent.map(|x| x.elapsed() < TIME_HEARTBEAT).unwrap_or(false) {
                    continue;
                }
                last_sent = Some(Instant::now());
                let mut v = Value::default();
                v["id"] = json!(id);
                v["uuid"] = json!(crate::encode64(hbb_common::get_uuid()));
                v["ver"] = json!(hbb_common::get_version_number(crate::VERSION));
                if !conns.is_empty() {
                    v["conns"] = json!(conns);
                }
                let modified_at = LocalConfig::get_option("strategy_timestamp").parse::<i64>().unwrap_or(0);
                v["modified_at"] = json!(modified_at);
                #[cfg(target_os = "android")]
                if requires_device_auth {
                    let policy_revision = LocalConfig::get_option(crate::android_provisioning::UNATTENDED_REVISION_OPTION)
                        .parse::<i64>()
                        .unwrap_or(0);
                    let provisioning_revision = LocalConfig::get_option(crate::android_provisioning::POLICY_REVISION_OPTION)
                        .parse::<i64>()
                        .unwrap_or(policy_revision);
                    v["unattended_status"] = json!({
                        "policy_revision": policy_revision,
                        "status": LocalConfig::get_option("android-unattended-status"),
                        "root_executor": LocalConfig::get_option("android-unattended-root-executor"),
                        "root_available": LocalConfig::get_option("android-unattended-root-available") == "Y",
                        "screen_capture_ready": LocalConfig::get_option("android-unattended-screen-capture-ready") == "Y",
                        "accessibility_ready": LocalConfig::get_option("android-unattended-accessibility-ready") == "Y",
                        "service_running": LocalConfig::get_option("android-unattended-service-running") == "Y",
                        "last_error": LocalConfig::get_option("android-unattended-last-error"),
                    });
                    v["server_profile_status"] = json!({
                        "policy_revision": provisioning_revision,
                        "active_source": crate::android_provisioning::server_profile_source(),
                        "connected": hbb_common::config::get_online_state() > 0,
                    });
                }
                #[cfg(target_os = "android")]
                let heartbeat_response = if requires_device_auth {
                    let Some(state) = device_auth.as_mut() else {
                        continue;
                    };
                    signed_device_post(
                        url.clone(),
                        v.to_string(),
                        state,
                    )
                    .await
                } else {
                    crate::post_request_with_status(url.clone(), v.to_string(), "").await
                };
                #[cfg(not(target_os = "android"))]
                let heartbeat_response = crate::post_request_with_status(url.clone(), v.to_string(), "").await;
                if let Ok((status, s)) = heartbeat_response {
                    #[cfg(target_os = "android")]
                    if requires_device_auth && matches!(status, 401 | 409) {
                        clear_device_registration();
                        device_auth = None;
                        *PRO.lock().unwrap() = false;
                        continue;
                    }
                    if !(200..300).contains(&status) {
                        continue;
                    }
                    if let Ok(mut rsp) = serde_json::from_str::<HashMap::<&str, Value>>(&s) {
                        if rsp.remove("sysinfo").is_some() {
                            info_uploaded.uploaded = false;
                            config::Status::set("sysinfo_hash", "".to_owned());
                            log::info!("sysinfo required to forcely update");
                        }
                        if let Some(conns)  = rsp.remove("disconnect") {
                                if let Ok(conns) = serde_json::from_value::<Vec<i32>>(conns) {
                                    SENDER.lock().unwrap().send(conns).ok();
                                }
                        }
                        let rsp_modified_at = rsp.remove("modified_at")
                            .and_then(|value| serde_json::from_value::<i64>(value).ok());
                        let mut policy_applied = false;
                        if let Some(strategy) = rsp.remove("strategy") {
                            if let Ok(mut strategy) = serde_json::from_value::<StrategyOptions>(strategy) {
                                #[cfg(target_os = "android")]
                                if requires_device_auth {
                                    if let Some(envelope) = strategy.extra.remove("android_provisioning") {
                                        let uuid = crate::encode64(hbb_common::get_uuid());
                                        match crate::android_provisioning::apply_policy(&envelope, &id, &uuid) {
                                            Ok(_) => policy_applied = true,
                                            Err(error) => log::warn!("Provisioning policy rejected: {}", error),
                                        }
                                    }
                                }
                                log::info!("strategy updated");
                                handle_config_options(strategy.config_options);
                            }
                        }
                        if let Some(revision) = rsp_modified_at {
                            #[cfg(target_os = "android")]
                            let can_store_revision = !requires_device_auth || revision == modified_at || policy_applied;
                            #[cfg(not(target_os = "android"))]
                            let can_store_revision = true;
                            if can_store_revision && revision != modified_at {
                                LocalConfig::set_option("strategy_timestamp".to_string(), revision.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn heartbeat_target() -> (String, bool) {
    #[cfg(target_os = "android")]
    if crate::android_provisioning::is_configured() {
        let server = crate::android_provisioning::provisioning_api_server().await;
        if server.is_empty() {
            return (String::new(), true);
        }
        return (format!("{}/api/device/heartbeat", server), true);
    }
    let url = crate::common::get_api_server(
        Config::get_option("api-server"),
        Config::get_option("custom-rendezvous-server"),
    );
    if url.is_empty() || crate::is_public(&url) {
        return (String::new(), false);
    }
    (format!("{}/api/heartbeat", url), false)
}

#[cfg(target_os = "android")]
struct DeviceAuthState {
    api_server: String,
    rustdesk_id: String,
    device_id: i64,
    next_sequence: i64,
}

#[cfg(target_os = "android")]
#[derive(Deserialize)]
struct DeviceRegistrationResponse {
    accepted: bool,
    #[serde(default)]
    device_id: i64,
    #[serde(default)]
    last_sequence: i64,
    #[serde(default)]
    server_time: i64,
}

#[cfg(target_os = "android")]
fn device_identity_hash(api_server: &str, id: &str) -> String {
    use hbb_common::sodiumoxide::crypto::hash::sha256;
    let mut identity = Vec::with_capacity(api_server.len() + id.len() + 1);
    identity.extend_from_slice(api_server.as_bytes());
    identity.push(0);
    identity.extend_from_slice(id.as_bytes());
    crate::encode64(sha256::hash(&identity).0)
}

#[cfg(target_os = "android")]
fn clear_device_registration() {
    LocalConfig::set_option(DEVICE_ID_OPTION.to_owned(), String::new());
    LocalConfig::set_option(DEVICE_SEQUENCE_OPTION.to_owned(), String::new());
    LocalConfig::set_option(DEVICE_API_HASH_OPTION.to_owned(), String::new());
}

#[cfg(target_os = "android")]
fn cached_device_auth(api_server: &str, id: &str) -> Option<DeviceAuthState> {
    if LocalConfig::get_option(DEVICE_API_HASH_OPTION) != device_identity_hash(api_server, id) {
        return None;
    }
    let device_id = LocalConfig::get_option(DEVICE_ID_OPTION)
        .parse::<i64>()
        .ok()?;
    let next_sequence = LocalConfig::get_option(DEVICE_SEQUENCE_OPTION)
        .parse::<i64>()
        .ok()?
        .max(1);
    (device_id > 0).then(|| DeviceAuthState {
        api_server: api_server.to_owned(),
        rustdesk_id: id.to_owned(),
        device_id,
        next_sequence,
    })
}

#[cfg(target_os = "android")]
fn registration_message(id: &str, uuid: &str, public_key: &[u8], timestamp: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + id.len() + uuid.len() + public_key.len());
    message.extend_from_slice(b"RUD-DEVICE-REGISTER\0");
    for value in [id, uuid] {
        message.extend_from_slice(value.as_bytes());
        message.push(0);
    }
    message.extend_from_slice(public_key);
    message.push(0);
    message.extend_from_slice(timestamp.to_string().as_bytes());
    message.push(0);
    message
}

#[cfg(target_os = "android")]
async fn register_device(api_server: &str, id: &str) -> Option<DeviceAuthState> {
    if let Some(state) = cached_device_auth(api_server, id) {
        return Some(state);
    }
    use hbb_common::sodiumoxide::crypto::{auth, sign};
    let key_pair = Config::get_key_pair();
    let secret_key = match sign::SecretKey::from_slice(&key_pair.0) {
        Some(key) => key,
        None => {
            log::error!("Device registration failed: invalid device key");
            return None;
        }
    };
    if key_pair.1.len() != sign::PUBLICKEYBYTES {
        log::error!("Device registration failed: invalid device public key");
        return None;
    }
    let enrollment_key = match crate::android_provisioning::device_enrollment_key() {
        Ok(key) => key,
        Err(error) => {
            log::error!("Device registration failed: {}", error);
            return None;
        }
    };
    let uuid = crate::encode64(hbb_common::get_uuid());
    let mut timestamp = hbb_common::get_time() / 1000;
    for attempt in 0..2 {
        let message = registration_message(id, &uuid, &key_pair.1, timestamp);
        let signature = sign::sign_detached(&message, &secret_key);
        let proof = auth::authenticate(&message, &enrollment_key);
        let body = json!({
            "id": id,
            "uuid": &uuid,
            "public_key": crate::encode64(&key_pair.1),
            "timestamp": timestamp,
            "signature": crate::encode64(signature.to_bytes()),
            "enrollment_proof": crate::encode64(proof.0),
        })
        .to_string();
        let response = crate::post_request_with_status(
            format!("{}/api/device/register", api_server),
            body,
            "",
        )
        .await;
        let Ok((_, body)) = response else {
            log::warn!("Device registration request failed");
            return None;
        };
        let Ok(response) = serde_json::from_str::<DeviceRegistrationResponse>(&body) else {
            log::warn!("Device registration response rejected");
            return None;
        };
        if response.accepted && response.device_id > 0 {
            let next_sequence = response.last_sequence.saturating_add(1).max(1);
            LocalConfig::set_option(DEVICE_ID_OPTION.to_owned(), response.device_id.to_string());
            LocalConfig::set_option(DEVICE_SEQUENCE_OPTION.to_owned(), next_sequence.to_string());
            LocalConfig::set_option(
                DEVICE_API_HASH_OPTION.to_owned(),
                device_identity_hash(api_server, id),
            );
            return Some(DeviceAuthState {
                api_server: api_server.to_owned(),
                rustdesk_id: id.to_owned(),
                device_id: response.device_id,
                next_sequence,
            });
        }
        if attempt == 0 && response.server_time > 0 {
            timestamp = response.server_time;
            continue;
        }
        log::warn!("Device registration was rejected");
        return None;
    }
    None
}

#[cfg(target_os = "android")]
fn device_request_message(device_id: i64, sequence: i64, payload: &[u8]) -> Vec<u8> {
    use hbb_common::sodiumoxide::crypto::hash::sha256;
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(b"RUD-DEVICE-REQUEST\0");
    for value in [device_id, sequence] {
        message.extend_from_slice(value.to_string().as_bytes());
        message.push(0);
    }
    message.extend_from_slice(&sha256::hash(payload).0);
    message
}

#[cfg(target_os = "android")]
async fn signed_device_post(
    url: String,
    payload: String,
    state: &mut DeviceAuthState,
) -> hbb_common::ResultType<(u16, String)> {
    use hbb_common::sodiumoxide::crypto::sign;
    let key_pair = Config::get_key_pair();
    let secret_key = sign::SecretKey::from_slice(&key_pair.0)
        .ok_or_else(|| hbb_common::anyhow::anyhow!("Invalid device signing key"))?;
    let sequence = state.next_sequence;
    state.next_sequence = state.next_sequence.saturating_add(1);
    LocalConfig::set_option(
        DEVICE_SEQUENCE_OPTION.to_owned(),
        state.next_sequence.to_string(),
    );
    let signature = sign::sign_detached(
        &device_request_message(state.device_id, sequence, payload.as_bytes()),
        &secret_key,
    );
    let body = json!({
        "device_id": state.device_id,
        "sequence": sequence,
        "payload": crate::encode64(payload.as_bytes()),
        "signature": crate::encode64(signature.to_bytes()),
    })
    .to_string();
    crate::post_request_with_status(url, body, "").await
}

fn handle_config_options(config_options: HashMap<String, String>) {
    let mut options = Config::get_options();
    let default_settings = config::DEFAULT_SETTINGS.read().unwrap().clone();
    config_options
        .iter()
        .map(|(k, v)| {
            // Priority: user config > default advanced options.
            // Only when default advanced options are also empty, remove user option (fallback to built-in default);
            // otherwise insert an empty value so user config remains present.
            if v.is_empty() && default_settings.get(k).map_or("", |v| v).is_empty() {
                options.remove(k);
            } else {
                options.insert(k.to_string(), v.to_string());
            }
        })
        .count();
    Config::set_options(options);
}

#[allow(unused)]
#[cfg(not(any(target_os = "ios")))]
pub fn is_pro() -> bool {
    PRO.lock().unwrap().clone()
}

// Fire-and-forget by design: the switch flow must not block on this POST.
// If the device clock is outside the server's accepted window, the server
// returns its current Unix time and this task re-signs and retries once.
#[cfg(feature = "flutter")]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn register_switch_grant(switch_uuid: String) {
    tokio::spawn(async move {
        let api_server = crate::ui_interface::get_api_server();
        if api_server.is_empty() || crate::is_public(&api_server) {
            return;
        }
        use hbb_common::sodiumoxide::crypto::{hash::sha256, sign};
        let switch_code = crate::encode64(sha256::hash(switch_uuid.as_bytes()).0);
        let switch_code_verifier = switch_code_verifier(&switch_code);
        let timestamp = (hbb_common::get_time() / 1000).to_string();
        let id = Config::get_id();
        let kp = Config::get_key_pair();
        let Some(sk) = sign::SecretKey::from_slice(&kp.0) else {
            log::error!("Failed to register switch grant: no device key");
            return;
        };
        let url = format!("{}/api/switch-grant", api_server);
        let mut timestamp = timestamp;
        for attempt in 0..2 {
            let signature = sign::sign_detached(
                &switch_grant_signed_msg(&id, &switch_code_verifier, &timestamp),
                &sk,
            );
            let body = json!({
                "id": &id,
                "switch_code_verifier": &switch_code_verifier,
                "timestamp": &timestamp,
                "signature": crate::encode64(signature.to_bytes()),
            })
            .to_string();
            let response = match crate::post_request(url.clone(), body, "").await {
                Ok(response) => response,
                Err(e) => {
                    log::error!("Failed to register switch grant: {}", e);
                    return;
                }
            };
            let response = match serde_json::from_str::<Value>(&response) {
                Ok(response) => response,
                Err(e) => {
                    log::error!("Failed to register switch grant: invalid response: {}", e);
                    return;
                }
            };
            match response.get("accepted").and_then(Value::as_bool) {
                Some(true) => return,
                Some(false) => {}
                None => {
                    log::error!("Failed to register switch grant: missing accepted response");
                    return;
                }
            }
            let Some(server_time) = response["server_time"].as_i64() else {
                log::error!("Failed to register switch grant: rejected by server");
                return;
            };
            if attempt == 0 {
                log::warn!("Switch grant timestamp rejected, retrying with server time");
                timestamp = server_time.to_string();
            } else {
                log::error!("Failed to register switch grant after retrying with server time");
            }
        }
    });
}

#[cfg(feature = "flutter")]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn switch_code_verifier(switch_code: &str) -> String {
    use hbb_common::sodiumoxide::crypto::hash::sha256;

    let prefix = b"switch-grant-verifier\0";
    let mut msg = Vec::with_capacity(prefix.len() + switch_code.len());
    msg.extend_from_slice(prefix);
    msg.extend_from_slice(switch_code.as_bytes());
    crate::encode64(sha256::hash(&msg).0)
}

#[cfg(feature = "flutter")]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn switch_grant_signed_msg(id: &str, switch_code_verifier: &str, timestamp: &str) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(13 + id.len() + 1 + switch_code_verifier.len() + 1 + timestamp.len());
    msg.extend_from_slice(b"switch-grant\0");
    msg.extend_from_slice(id.as_bytes());
    msg.push(0);
    msg.extend_from_slice(switch_code_verifier.as_bytes());
    msg.push(0);
    msg.extend_from_slice(timestamp.as_bytes());
    msg
}

#[cfg(all(
    test,
    feature = "flutter",
    not(any(target_os = "android", target_os = "ios"))
))]
mod tests {
    use super::{switch_code_verifier, switch_grant_signed_msg};

    #[test]
    fn test_switch_code_verifier_is_not_raw_switch_code() {
        let switch_code = "code-abc";
        let verifier = switch_code_verifier(switch_code);
        assert_ne!(verifier, switch_code);
        assert_eq!(verifier, switch_code_verifier(switch_code));
        assert_eq!(verifier, "dMIn3uiPe77XodFB5IKi7PrKJ7l7+zVquNn0ObSaHQc=");
    }

    #[test]
    fn test_switch_grant_signed_msg_layout() {
        let expected: Vec<u8> = [
            &b"switch-grant\0"[..],
            b"id1",
            b"\0",
            b"c1",
            b"\0",
            b"1700000000",
        ]
        .concat();
        assert_eq!(switch_grant_signed_msg("id1", "c1", "1700000000"), expected);
    }
}
