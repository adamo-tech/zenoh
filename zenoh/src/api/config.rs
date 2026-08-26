//
// Copyright (c) 2024 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
use std::{
    env, fmt,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use zenoh_config::ExpandedConfig;
use zenoh_result::{bail, ZResult};

/// Certificate or private-key material for Zenoh's TLS-based links.
///
/// TLS and QUIC share this configuration. File paths are retained in the
/// configuration and read when a link is opened. PEM values are immediately
/// moved into Zenoh's redacted, zeroizing secret storage.
#[derive(Clone, Copy)]
pub enum TlsCredential<'a> {
    File(&'a Path),
    Pem(&'a str),
}

impl fmt::Debug for TlsCredential<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => formatter.debug_tuple("File").field(path).finish(),
            Self::Pem(_) => formatter.write_str("Pem([redacted])"),
        }
    }
}

/// A certificate chain and its corresponding private key.
#[derive(Clone, Copy, Debug)]
pub struct TlsIdentity<'a> {
    certificate: TlsCredential<'a>,
    private_key: TlsCredential<'a>,
}

impl<'a> TlsIdentity<'a> {
    pub const fn new(certificate: TlsCredential<'a>, private_key: TlsCredential<'a>) -> Self {
        Self {
            certificate,
            private_key,
        }
    }
}

#[derive(Clone, Copy)]
enum TlsCredentialSlot {
    RootCa,
    ListenCertificate,
    ListenPrivateKey,
    ConnectCertificate,
    ConnectPrivateKey,
}

/// Zenoh configuration.
///
/// The zenoh configuration is unstable, so no direct access to the fields is provided.
/// The only way to change the configuration is to load the JSON configuration from a file or a string,
/// with [`Config::from_file`](crate::config::Config::from_file) or
/// [`Config::from_json5`](crate::config::Config::from_json5),
/// or to use the [`Config::insert_json5`](crate::config::Config::insert_json5)
/// and [`Config::remove`](crate::config::Config::remove) methods to modify the configuration tree.
///
/// Example configuration file:
#[doc = concat!(
    "```json5\n",
    include_str!("../../DEFAULT_CONFIG.json5"),
    "\n```"
)]
///
/// Most options are optional as a way to keep defaults flexible. Some of the options have different
/// default values depending on the rest of the configuration.
///
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Config(pub(crate) zenoh_config::Config);

impl Config {
    /// Default environment variable containing the file path used in [`Config::from_env`].
    pub const DEFAULT_CONFIG_PATH_ENV: &'static str = "ZENOH_CONFIG";

    /// Load configuration from the file path specified in the [`Self::DEFAULT_CONFIG_PATH_ENV`]
    /// environment variable.
    pub fn from_env() -> ZResult<Self> {
        let path = env::var(Self::DEFAULT_CONFIG_PATH_ENV)?;
        Ok(Config(zenoh_config::Config::from_file(Path::new(&path))?))
    }

    /// Load configuration from the file at `path`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> ZResult<Self> {
        Ok(Config(zenoh_config::Config::from_file(path)?))
    }

    /// Load configuration from the JSON5 string `input`.
    pub fn from_json5(input: &str) -> ZResult<Config> {
        match zenoh_config::Config::from_deserializer(&mut json5::Deserializer::from_str(input)?) {
            Ok(config) => Ok(Config(config)),
            Err(Ok(_)) => {
                Err(zerror!("The config was correctly deserialized, but it is invalid").into())
            }
            Err(Err(err)) => Err(err.into()),
        }
    }

    pub fn remove<K: AsRef<str>>(&mut self, key: K) -> ZResult<()> {
        self.0.remove(key.as_ref())
    }

    /// See [`zenoh_config::Config::try_remove_json5_array_item`].
    pub fn try_remove_json5_array_item<K: AsRef<str>>(&mut self, key: K) -> ZResult<bool> {
        self.0.try_remove_json5_array_item(key)
    }

    /// Inserts configuration value `value` at `key`.
    pub fn insert_json5(&mut self, key: &str, value: &str) -> ZResult<()> {
        self.0
            .insert_json5(key, value)
            .map_err(|err| zerror!("{err}").into())
    }

    /// See [`zenoh_config::Config::try_insert_json5_array_item`].
    pub fn try_insert_json5_array_item(&mut self, key: &str, value: &str) -> ZResult<bool> {
        self.0
            .try_insert_json5_array_item(key, value)
            .map_err(|err| zerror!("{err}").into())
    }

    /// Returns a JSON string containing the configuration at `key`.
    pub fn get_json(&self, key: &str) -> ZResult<String> {
        self.0.get_json(key).map_err(|err| zerror!("{err}").into())
    }

    /// Replace the custom trust anchor used by TLS and QUIC links.
    ///
    /// Passing `None` removes the custom trust anchor. Connecting links then
    /// use Zenoh's built-in WebPKI roots.
    pub fn set_tls_root_ca(&mut self, credential: Option<TlsCredential<'_>>) -> ZResult<()> {
        let mut updated = self.0.clone();
        set_tls_credential(&mut updated, TlsCredentialSlot::RootCa, credential)?;
        self.0 = updated;
        Ok(())
    }

    /// Replace or clear the identity presented by TLS and QUIC listeners.
    pub fn set_tls_listen_identity(&mut self, identity: Option<TlsIdentity<'_>>) -> ZResult<()> {
        let mut updated = self.0.clone();
        let (certificate, private_key) = identity
            .map(|identity| (Some(identity.certificate), Some(identity.private_key)))
            .unwrap_or((None, None));
        set_tls_credential(
            &mut updated,
            TlsCredentialSlot::ListenCertificate,
            certificate,
        )?;
        set_tls_credential(
            &mut updated,
            TlsCredentialSlot::ListenPrivateKey,
            private_key,
        )?;
        self.0 = updated;
        Ok(())
    }

    /// Replace or clear the identity presented by connecting TLS and QUIC
    /// links when mutual authentication is enabled.
    pub fn set_tls_connect_identity(&mut self, identity: Option<TlsIdentity<'_>>) -> ZResult<()> {
        let mut updated = self.0.clone();
        let (certificate, private_key) = identity
            .map(|identity| (Some(identity.certificate), Some(identity.private_key)))
            .unwrap_or((None, None));
        set_tls_credential(
            &mut updated,
            TlsCredentialSlot::ConnectCertificate,
            certificate,
        )?;
        set_tls_credential(
            &mut updated,
            TlsCredentialSlot::ConnectPrivateKey,
            private_key,
        )?;
        self.0 = updated;
        Ok(())
    }

    /// Enable or disable mutual authentication for TLS and QUIC links.
    pub fn set_tls_mutual_authentication(&mut self, enabled: bool) -> ZResult<()> {
        self.0
            .transport
            .link
            .tls
            .set_enable_mtls(Some(enabled))
            .map(|_| ())
            .map_err(|_| zerror!("Zenoh rejected the TLS mutual-authentication setting").into())
    }

    // REVIEW(fuzzypixelz): the error variant of the Result is a Result because this does
    // deserialization AND validation.
    #[zenoh_macros::unstable]
    // TODO(yellowhatter): clippy says that Error here is extremely large (1k)
    #[allow(clippy::result_large_err)]
    pub fn from_deserializer<'d, D: serde::Deserializer<'d>>(
        d: D,
    ) -> Result<Self, Result<Self, D::Error>>
    where
        Self: serde::Deserialize<'d>,
    {
        match zenoh_config::Config::from_deserializer(d) {
            Ok(config) => Ok(Config(config)),
            Err(result) => match result {
                Ok(config) => Err(Ok(Config(config))),
                Err(err) => Err(Err(err)),
            },
        }
    }
}

fn set_tls_credential(
    config: &mut zenoh_config::Config,
    slot: TlsCredentialSlot,
    credential: Option<TlsCredential<'_>>,
) -> ZResult<()> {
    let (file, base64) = match credential {
        Some(TlsCredential::File(path)) => {
            if path.as_os_str().is_empty() {
                bail!("TLS credential file path must not be empty");
            }
            let path = path
                .to_str()
                .ok_or_else(|| zerror!("TLS credential file path is not valid UTF-8: {path:?}"))?;
            (Some(path.to_owned()), None)
        }
        Some(TlsCredential::Pem(pem)) => {
            if pem.trim().is_empty() {
                bail!("TLS credential PEM must not be empty");
            }
            let encoded = STANDARD.encode(pem);
            (None, Some(zenoh_config::secret_value(encoded)))
        }
        None => (None, None),
    };

    let tls = &mut config.transport.link.tls;
    macro_rules! set_pair {
        ($file_setter:ident, $base64_setter:ident) => {{
            tls.$file_setter(file)
                .map_err(|_| zerror!("Zenoh rejected a TLS credential file"))?;
            tls.$base64_setter(base64)
                .map_err(|_| zerror!("Zenoh rejected inline TLS credential material"))?;
        }};
    }
    match slot {
        TlsCredentialSlot::RootCa => {
            set_pair!(set_root_ca_certificate, set_root_ca_certificate_base64)
        }
        TlsCredentialSlot::ListenCertificate => {
            set_pair!(set_listen_certificate, set_listen_certificate_base64)
        }
        TlsCredentialSlot::ListenPrivateKey => {
            set_pair!(set_listen_private_key, set_listen_private_key_base64)
        }
        TlsCredentialSlot::ConnectCertificate => {
            set_pair!(set_connect_certificate, set_connect_certificate_base64)
        }
        TlsCredentialSlot::ConnectPrivateKey => {
            set_pair!(set_connect_private_key, set_connect_private_key_base64)
        }
    }
    Ok(())
}

#[zenoh_macros::unstable]
impl std::ops::Deref for Config {
    type Target = zenoh_config::Config;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[zenoh_macros::unstable]
impl std::ops::DerefMut for Config {
    fn deref_mut(&mut self) -> &mut <Self as std::ops::Deref>::Target {
        &mut self.0
    }
}

#[doc(hidden)]
impl From<zenoh_config::Config> for Config {
    fn from(value: zenoh_config::Config) -> Self {
        Self(value)
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub type Notification = Arc<str>;

struct NotifierInner<T> {
    inner: Mutex<T>,
    subscribers: Mutex<Vec<flume::Sender<Notification>>>,
}

/// The wrapper for a [`Config`] that allows to subscribe to changes.
/// This type is returned by [`Session::config`](crate::Session::config) and allows
/// the `Session` to immediately react to changes applied to the configuration.
pub struct Notifier<T> {
    inner: Arc<NotifierInner<T>>,
}

impl<T> fmt::Debug for Notifier<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Notifier").field(&"..").finish()
    }
}

impl<T> Clone for Notifier<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

fn ensure_config_key_is_dynamically_writable(key: &str) -> ZResult<()> {
    if !key.starts_with("plugins/") {
        bail!(
            "Error inserting conf value {} : updating config is only \
                supported for keys starting with `plugins/`",
            key
        );
    }
    Ok(())
}

impl Notifier<ExpandedConfig> {
    pub fn new(inner: ExpandedConfig) -> Self {
        Notifier {
            inner: Arc::new(NotifierInner {
                inner: Mutex::new(inner),
                subscribers: Mutex::new(Vec::new()),
            }),
        }
    }

    #[cfg(feature = "plugins")]
    pub fn subscribe(&self) -> flume::Receiver<Notification> {
        let (tx, rx) = flume::unbounded();
        self.lock_subscribers().push(tx);
        rx
    }

    pub fn notify<K: AsRef<str>>(&self, key: K) {
        let key = key.as_ref();
        let key: Arc<str> = Arc::from(key);
        let mut marked = Vec::new();
        let mut subscribers = self.lock_subscribers();

        for (i, sub) in subscribers.iter().enumerate() {
            if sub.send(key.clone()).is_err() {
                marked.push(i)
            }
        }

        for i in marked.into_iter().rev() {
            subscribers.swap_remove(i);
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, ExpandedConfig> {
        self.lock_config()
    }

    fn lock_subscribers(&self) -> MutexGuard<'_, Vec<flume::Sender<Notification>>> {
        self.inner
            .subscribers
            .lock()
            .expect("acquiring Notifier's subscribers Mutex should not fail")
    }

    fn lock_config(&self) -> MutexGuard<'_, ExpandedConfig> {
        self.inner
            .inner
            .lock()
            .expect("acquiring Notifier's Config Mutex should not fail")
    }

    pub fn remove<K: AsRef<str>>(&self, key: K) -> ZResult<()> {
        self.lock_config().remove(key.as_ref())?;
        self.notify(key);
        Ok(())
    }

    pub fn try_remove_json5_array_item<K: AsRef<str>>(&self, key: K) -> ZResult<bool> {
        let applied = self
            .lock_config()
            .try_remove_json5_array_item(key.as_ref())?;
        if applied {
            self.notify(key);
        }
        Ok(applied)
    }

    pub fn insert_json5(&self, key: &str, value: &str) -> ZResult<()> {
        ensure_config_key_is_dynamically_writable(key)?;
        self.lock_config().insert_json5(key, value)?;
        self.notify(key);
        Ok(())
    }

    pub fn try_insert_json5_array_item(&self, key: &str, value: &str) -> ZResult<bool> {
        ensure_config_key_is_dynamically_writable(key)?;
        let applied = self.lock_config().try_insert_json5_array_item(key, value)?;
        if applied {
            self.notify(key);
        }
        Ok(applied)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use zenoh_config::{InterceptorFlow, QosOverwriteItemConf};

    use crate::Config;

    use super::{TlsCredential, TlsIdentity};

    #[test]
    fn typed_tls_credentials_replace_conflicting_representations() {
        let mut config = Config::default();

        config
            .set_tls_root_ca(Some(TlsCredential::Pem("root-ca-pem")))
            .unwrap();
        assert!(config.0.transport.link.tls.root_ca_certificate().is_none());
        assert!(config
            .0
            .transport
            .link
            .tls
            .root_ca_certificate_base64()
            .is_some());

        config
            .set_tls_root_ca(Some(TlsCredential::File(Path::new("/run/ca.pem"))))
            .unwrap();
        assert_eq!(
            config.0.transport.link.tls.root_ca_certificate().as_deref(),
            Some("/run/ca.pem")
        );
        assert!(config
            .0
            .transport
            .link
            .tls
            .root_ca_certificate_base64()
            .is_none());
    }

    #[test]
    fn typed_tls_identity_is_updated_atomically() {
        let mut config = Config::default();
        config
            .set_tls_listen_identity(Some(TlsIdentity::new(
                TlsCredential::File(Path::new("/run/server.pem")),
                TlsCredential::Pem("server-key-pem"),
            )))
            .unwrap();

        let tls = &config.0.transport.link.tls;
        assert_eq!(tls.listen_certificate().as_deref(), Some("/run/server.pem"));
        assert!(tls.listen_certificate_base64().is_none());
        assert!(tls.listen_private_key().is_none());
        assert!(tls.listen_private_key_base64().is_some());
    }

    #[test]
    fn runtime_try_insert_json5_array_item_rejects_non_plugin_keys() {
        let config = super::Notifier::new(zenoh_config::Config::default().expanded());
        let before = config.lock().get_json("qos/network").unwrap();

        let err = config
            .try_insert_json5_array_item(
                "qos/network/id=item1",
                r#"{
                    id: "item1",
                    messages: ["put"],
                    key_exprs: ["**"],
                    overwrite: { priority: "real_time" },
                    flows: ["egress"]
                }"#,
            )
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("supported for keys starting with `plugins/`"));
        assert_eq!(config.lock().get_json("qos/network").unwrap(), before);
    }

    #[test]
    fn insert_remove_json5_array_item() {
        let mut config = Config::default();

        let item1 = r#"{
            id: "item1",
            messages: ["put"],
            key_exprs: ["**"],
            overwrite: {
                priority: "real_time",
            },
            flows: ["egress"]
        }"#;
        assert!(config
            .try_insert_json5_array_item("qos/network/id=item1", item1)
            .unwrap());
        let items = serde_json::from_str::<Vec<QosOverwriteItemConf>>(
            &config.get_json("qos/network").unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id.as_ref().unwrap(), "item1");
        assert_eq!(
            *items[0].flows.as_ref().unwrap().first(),
            InterceptorFlow::Egress
        );

        let item1 = r#"{
            id: "item1",
            messages: ["put"],
            key_exprs: ["**"],
            overwrite: {
                priority: "real_time",
            },
            flows: ["ingress"]
        }"#;
        assert!(config
            .try_insert_json5_array_item("qos/network/id=item1", item1)
            .unwrap());
        let items = serde_json::from_str::<Vec<QosOverwriteItemConf>>(
            &config.get_json("qos/network").unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id.as_ref().unwrap(), "item1");
        assert_eq!(
            *items[0].flows.as_ref().unwrap().first(),
            InterceptorFlow::Ingress
        );

        let item2 = r#"{
            id: "item2",
            messages: ["put"],
            key_exprs: ["**"],
            overwrite: {
                priority: "real_time",
            },
            flows: ["egress"]
        }"#;
        assert!(config
            .try_insert_json5_array_item("qos/network/id=item2", item2)
            .unwrap());
        let items = serde_json::from_str::<Vec<QosOverwriteItemConf>>(
            &config.get_json("qos/network").unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id.as_ref().unwrap(), "item1");
        assert_eq!(
            *items[0].flows.as_ref().unwrap().first(),
            InterceptorFlow::Ingress
        );
        assert_eq!(items[1].id.as_ref().unwrap(), "item2");
        assert_eq!(
            *items[1].flows.as_ref().unwrap().first(),
            InterceptorFlow::Egress
        );

        assert!(config
            .try_remove_json5_array_item("qos/network/id=item2")
            .unwrap());
        let items = serde_json::from_str::<Vec<QosOverwriteItemConf>>(
            &config.get_json("qos/network").unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id.as_ref().unwrap(), "item1");
        assert_eq!(
            *items[0].flows.as_ref().unwrap().first(),
            InterceptorFlow::Ingress
        );

        assert!(config
            .try_remove_json5_array_item("qos/network/id=item1")
            .unwrap());
        let items = serde_json::from_str::<Vec<QosOverwriteItemConf>>(
            &config.get_json("qos/network").unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 0);
    }
}
