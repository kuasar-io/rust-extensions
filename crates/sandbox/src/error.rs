use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),

    #[error("Already exist: {0}")]
    AlreadyExist(String),

    #[error("Unimplemented: {0}")]
    Unimplemented(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<Error> for Status {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidArgument(s) => Status::invalid_argument(s),
            Error::NotFound(s) => Status::not_found(s),
            Error::IO(e) => Status::internal(e.to_string()),
            Error::AlreadyExist(s) => Status::already_exists(s),
            Error::Unimplemented(s) => Status::unimplemented(s),
            Error::ResourceExhausted(s) => Status::resource_exhausted(s),
            Error::Other(e) => Status::internal(format!("{}", e)),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
