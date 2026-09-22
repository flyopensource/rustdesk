use hbb_common::{
    anyhow::{anyhow, bail, Context},
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _},
    sodiumoxide::crypto::{hash::sha256, secretbox},
    ResultType,
};

const API_KEY_CONTEXT: &[u8] = b"RUD-DESKTOP-API\0";

pub fn validate_api_server(value: &str) -> ResultType<String> {
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

pub fn api_server(token: &str) -> ResultType<String> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.first() != Some(&"rud2") || parts.len() != 5 {
        bail!("Invalid enrollment token")
    }
    let selector = URL_SAFE_NO_PAD
        .decode(parts[1])
        .context("Invalid enrollment token selector")?;
    if selector.len() < 12 {
        bail!("Invalid enrollment token selector")
    }
    let secret = URL_SAFE_NO_PAD
        .decode(parts[2])
        .context("Invalid enrollment token secret")?;
    if secret.len() < 24 {
        bail!("Invalid enrollment token secret")
    }
    let nonce = secretbox::Nonce::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[3])
            .context("Invalid enrollment token nonce")?,
    )
    .ok_or_else(|| anyhow!("Invalid enrollment token nonce"))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(parts[4])
        .context("Invalid enrollment token API server")?;
    if ciphertext.len() <= secretbox::MACBYTES {
        bail!("Invalid enrollment token API server")
    }
    let mut key_material = Vec::with_capacity(API_KEY_CONTEXT.len() + secret.len());
    key_material.extend_from_slice(API_KEY_CONTEXT);
    key_material.extend_from_slice(&secret);
    let key = secretbox::Key(sha256::hash(&key_material).0);
    let plaintext = secretbox::open(&ciphertext, &nonce, &key)
        .map_err(|_| anyhow!("Invalid enrollment token API server"))?;
    let api_server = String::from_utf8(plaintext).context("Invalid enrollment token API server")?;
    validate_api_server(&api_server)
}
