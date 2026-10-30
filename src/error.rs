#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct MoodleError(String);

impl MoodleError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

pub type Result<T> = std::result::Result<T, MoodleError>;

impl From<MoodleError> for String {
    fn from(error: MoodleError) -> Self {
        error.0
    }
}
