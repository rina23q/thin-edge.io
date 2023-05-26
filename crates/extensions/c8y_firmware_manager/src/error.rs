#[derive(thiserror::Error, Debug)]
pub enum DirNotFound {
    #[error(
        "Directory {path} is not found. Run 'c8y-firmware-plugin --init' to create the directory."
    )]
    DirectoryNotFound { path: std::path::PathBuf },
}

#[derive(thiserror::Error, Debug)]
pub enum DirectoryError {
    #[error(transparent)]
    FromIoError(#[from] std::io::Error),

    #[error("Failed to parse response from child device with: {0}")]
    FromSerdeJsonError(#[from] serde_json::Error),

    #[error(transparent)]
    FromDirNotFound(#[from] DirNotFound),

    #[error(transparent)]
    FromFileError(#[from] tedge_utils::file::FileError),

    // Consider to improve
    #[error("The given sha256 is mismatched with downloaded file")]
    MismatchedSha256,
}

#[derive(thiserror::Error, Debug)]
pub enum JwtRetrievalError {
    #[error("Failed to retrieve JWT token.")]
    NoJwtToken,

    #[error(transparent)]
    FromChannelError(#[from] tedge_actors::ChannelError),
}

#[derive(thiserror::Error, Debug)]
pub enum FirmwareRequestResponseError {
    #[error(transparent)]
    FromMqttError(#[from] tedge_mqtt_ext::MqttError),

    #[error("Invalid topic received from child device: {topic}")]
    InvalidTopicFromChildOperation { topic: String },

    #[error("Failed to parse response from child device with: {0}")]
    FromSerdeJsonError(#[from] serde_json::Error),
}
