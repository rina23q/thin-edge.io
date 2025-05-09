use tedge_config::tedge_toml::MultiError;

#[derive(thiserror::Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum TEdgeError {
    #[error("TOML parse error")]
    FromTomlParse(#[from] toml::de::Error),

    #[error("TOML serialization error")]
    FromInvalidToml(#[from] toml::ser::Error),

    #[error("I/O error")]
    FromIo(#[from] std::io::Error),

    #[error(transparent)]
    FromPaths(#[from] tedge_utils::paths::PathsError),

    #[error(transparent)]
    FromTEdgeConfig(#[from] tedge_config::TEdgeConfigError),

    #[error(transparent)]
    FromTEdgeConfigSetting(#[from] tedge_config::ConfigSettingError),

    #[error(transparent)]
    FromSystemServiceError(#[from] crate::system_services::SystemServiceError),

    #[error(transparent)]
    FromSystemToml(#[from] tedge_config::SystemTomlError),

    #[error(transparent)]
    FromTEdgeConfigRead(#[from] tedge_config::tedge_toml::ReadError),

    #[error(transparent)]
    FromConfigNotSet(#[from] tedge_config::tedge_toml::ConfigNotSet),

    #[error(transparent)]
    FromMultiError(#[from] MultiError),

    #[error(transparent)]
    FromCredentialsFileError(#[from] c8y_api::http_proxy::CredentialsFileError),

    #[error(transparent)]
    FromAnyhow(#[from] anyhow::Error),

    #[error(transparent)]
    FromC8yEndPointConfigError(#[from] c8y_api::http_proxy::C8yEndPointConfigError),
}
