pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub(crate) type Result<T> = std::result::Result<T, BoxError>;

pub(crate) fn boxed(message: impl Into<String>) -> BoxError {
    Box::new(std::io::Error::other(message.into()))
}
