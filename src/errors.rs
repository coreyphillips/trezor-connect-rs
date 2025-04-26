use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HardwareError {
    #[error("Failed to initialize hardware wallet: {error_details}")]
    InitializationError {
        error_details: String,
    },

    #[error("I/O error: {error_details}")]
    IoError {
        error_details: String,
    },

    #[error("Failed to get executable directory")]
    ExecutableDirectoryError,

    #[error("Failed to communicate with hardware device: {error_details}")]
    CommunicationError {
        error_details: String,
    },

    #[error("JSON serialization/deserialization error: {error_details}")]
    JsonError {
        error_details: String,
    },
}