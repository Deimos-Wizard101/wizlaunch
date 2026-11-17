//! Credential storage on Linux.
//!
//! The Win32 build hands this to Credential Manager, where the blob is sealed
//! by DPAPI against the user's logon credentials. Linux has no equivalent we
//! can depend on: the Secret Service API needs a daemon (gnome-keyring,
//! kwallet) that a bare Wayland or headless session simply does not run.
//!
//! So the store is one file sealed with a passphrase: Argon2id stretches the
//! passphrase into a key, ChaCha20-Poly1305 seals the entire account map. The
//! whole map is one ciphertext, so the file reveals neither passwords nor which
//! accounts exist, and the AEAD tag means tampering is detected rather than
//! decrypted into garbage.
//!
//! The derived key is cached for the life of the process, so a launcher opening
//! several instances prompts once.

use crate::errors::VaultError;
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"DEIMOSCR";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;
/// ChaCha20-Poly1305 authentication tag.
const TAG_LEN: usize = 16;

/// Unlocked once per process, then reused. The salt is kept alongside the key:
/// if the store on disk is replaced, its salt will not match and the passphrase
/// is asked for again rather than a stale key being used to seal it.
static KEY_CACHE: Mutex<Option<([u8; SALT_LEN], [u8; 32])>> = Mutex::new(None);

#[derive(Serialize, Deserialize)]
struct Entry {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Store(BTreeMap<String, Entry>);

fn store_path() -> Result<PathBuf, VaultError> {
    Ok(super::config_dir()?.join("credentials.bin"))
}

fn random_bytes(buf: &mut [u8]) -> Result<(), VaultError> {
    getrandom::getrandom(buf)
        .map_err(|e| VaultError::CredentialWrite(format!("could not read system randomness: {e}")))
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], VaultError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::CredentialDecrypt(format!("key derivation failed: {e}")))?;
    Ok(key)
}

/// Return the cached key, or prompt for the passphrase and derive it.
/// `confirm` asks twice, for when the store is being created.
fn unlock(salt: &[u8; SALT_LEN], confirm: bool) -> Result<[u8; 32], VaultError> {
    let mut cache = KEY_CACHE.lock().unwrap();
    if let Some((cached_salt, key)) = *cache {
        if cached_salt == *salt {
            return Ok(key);
        }
    }

    let mut passphrase = super::prompt::prompt_passphrase(confirm)?;
    let derived = derive_key(&passphrase, salt);
    passphrase.zeroize();

    let key = derived?;
    *cache = Some((*salt, key));
    Ok(key)
}

/// Drop the cached key so a bad passphrase is re-prompted instead of retried.
fn forget_key() {
    *KEY_CACHE.lock().unwrap() = None;
}

/// Decrypt the store. A missing file is an empty store and prompts for nothing.
fn load() -> Result<(Store, [u8; SALT_LEN]), VaultError> {
    let path = store_path()?;

    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut salt = [0u8; SALT_LEN];
            random_bytes(&mut salt)?;
            return Ok((Store::default(), salt));
        }
        Err(e) => return Err(VaultError::MetadataIo(e.to_string())),
    };

    if raw.len() < HEADER_LEN + TAG_LEN || &raw[..MAGIC.len()] != MAGIC {
        return Err(VaultError::CredentialDecrypt(format!(
            "{} is not a wizlaunch credential store",
            path.display()
        )));
    }
    if raw[MAGIC.len()] != VERSION {
        return Err(VaultError::CredentialDecrypt(format!(
            "credential store version {} is newer than this build understands",
            raw[MAGIC.len()]
        )));
    }

    let salt_at = MAGIC.len() + 1;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw[salt_at..salt_at + SALT_LEN]);
    let nonce = Nonce::from_slice(&raw[salt_at + SALT_LEN..HEADER_LEN]);

    let key = unlock(&salt, false)?;
    let mut plain = ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(nonce, &raw[HEADER_LEN..])
        .map_err(|_| {
            forget_key();
            VaultError::CredentialDecrypt(
                "wrong passphrase, or the credential store has been modified".to_string(),
            )
        })?;

    let parsed = serde_json::from_slice(&plain);
    plain.zeroize();
    Ok((parsed?, salt))
}

fn save(store: &Store, salt: &[u8; SALT_LEN], key: &[u8; 32]) -> Result<(), VaultError> {
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce)?;

    let mut plain = serde_json::to_vec(store)?;
    let sealed = ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
        .map_err(|e| VaultError::CredentialWrite(format!("could not seal the store: {e}")));
    plain.zeroize();

    let mut out = Vec::with_capacity(HEADER_LEN + sealed.as_ref().map_or(0, Vec::len));
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed?);

    write_private(&store_path()?, &out)
}

/// Write owner-only, and through a temporary file so an interrupted save cannot
/// leave a store that no longer decrypts.
fn write_private(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn write_credential(nickname: &str, username: &str, password: &str) -> Result<(), VaultError> {
    let creating = !store_path()?.exists();
    let (mut store, salt) = load()?;
    let key = unlock(&salt, creating)?;

    store.0.insert(
        nickname.to_string(),
        Entry {
            username: username.to_string(),
            password: password.to_string(),
        },
    );
    save(&store, &salt, &key)
}

pub fn read_credential(nickname: &str) -> Result<(String, String), VaultError> {
    let (store, _) = load()?;
    store
        .0
        .get(nickname)
        .map(|e| (e.username.clone(), e.password.clone()))
        .ok_or_else(|| VaultError::CredentialNotFound(nickname.to_string()))
}

pub fn delete_credential(nickname: &str) -> Result<(), VaultError> {
    let (mut store, salt) = load()?;
    if store.0.remove(nickname).is_none() {
        return Err(VaultError::CredentialNotFound(nickname.to_string()));
    }
    let key = unlock(&salt, false)?;
    save(&store, &salt, &key)
}

pub fn list_credential_nicknames() -> Result<Vec<String>, VaultError> {
    // Listing an absent store must not demand a passphrase for nothing.
    if !store_path()?.exists() {
        return Ok(Vec::new());
    }
    let (store, _) = load()?;
    Ok(store.0.keys().cloned().collect())
}
