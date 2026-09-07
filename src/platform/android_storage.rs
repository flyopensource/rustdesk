use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "android")]
pub fn shared_root() -> Option<String> {
    use hbb_common::config::LocalConfig;
    if LocalConfig::get_option("android-unattended-enabled") != "Y"
        || LocalConfig::get_option("android-unattended-all-files-access-ready") != "Y"
    {
        return None;
    }
    let root = LocalConfig::get_option("android-unattended-shared-storage-root");
    if root.is_empty() {
        None
    } else {
        Some(root)
    }
}

#[cfg(target_os = "android")]
pub fn allows(path: &str) -> bool {
    shared_root().map_or(false, |root| {
        allowed_under(Path::new(&root), Path::new(path))
    })
}

#[cfg(target_os = "android")]
pub fn is_shared_root(path: &str) -> bool {
    shared_root().map_or(false, |root| {
        match (
            Path::new(&root).canonicalize(),
            Path::new(path).canonicalize(),
        ) {
            (Ok(root), Ok(path)) => root == path,
            _ => false,
        }
    })
}

pub fn allowed_under(root: &Path, path: &Path) -> bool {
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return false;
    }
    let root = match root.canonicalize() {
        Ok(root) if root.parent().is_some() => root,
        _ => return false,
    };
    let mut base = path.to_path_buf();
    let mut tail = Vec::new();
    let resolved: PathBuf = loop {
        match base.canonicalize() {
            Ok(mut resolved) => {
                for part in tail.iter().rev() {
                    resolved.push(part);
                }
                break resolved;
            }
            Err(_) => {
                // Do not treat dangling symlinks as not-yet-created directories.
                if base.symlink_metadata().is_ok() {
                    return false;
                }
                let name = match base.file_name() {
                    Some(name) => name.to_os_string(),
                    None => return false,
                };
                tail.push(name);
                if !base.pop() {
                    return false;
                }
            }
        }
    };
    resolved.starts_with(&root) && !resolved.starts_with(root.join("Android"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_storage_boundaries() {
        let dir = std::env::temp_dir().join(format!("rustdesk-storage-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("shared/Download")).unwrap();
        std::fs::create_dir_all(dir.join("private")).unwrap();
        let root = dir.join("shared");
        assert!(allowed_under(&root, &root.join("Download/new/file.txt")));
        assert!(allowed_under(&root, &root));
        assert!(!allowed_under(&root, &root.join("../private")));
        assert!(!allowed_under(&root, &dir.join("private")));
        assert!(!allowed_under(
            &root,
            &root.join("Android/data/another.app")
        ));
        assert!(!allowed_under(&root, Path::new("relative")));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.join("private"), root.join("escape")).unwrap();
            assert!(!allowed_under(&root, &root.join("escape/new")));
            std::os::unix::fs::symlink(dir.join("absent"), root.join("dangling")).unwrap();
            assert!(!allowed_under(&root, &root.join("dangling/new")));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
