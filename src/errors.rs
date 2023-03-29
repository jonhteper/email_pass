use bcrypt::BcryptError;
use std::fmt::{Debug, Display, Formatter};
use zxcvbn::ZxcvbnError;

#[derive(Debug)]
pub enum Error {
    PasswordLength,
    UnsafePassword,
    Bcrypt(BcryptError),
    Zxcvbn(ZxcvbnError),
    Regex(regex::Error),
    InexistentEncryptPassword,
    WrongPassword,
    EmailFormat,
    EmailLength,
}

impl From<BcryptError> for Error {
    fn from(err: BcryptError) -> Self {
        Self::Bcrypt(err)
    }
}

impl From<ZxcvbnError> for Error {
    fn from(err: ZxcvbnError) -> Self {
        Self::Zxcvbn(err)
    }
}

impl From<regex::Error> for Error {
    fn from(err: regex::Error) -> Self {
        Self::Regex(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Bcrypt(err) => Display::fmt(err, f),
            Error::Zxcvbn(err) => Display::fmt(err, f),
            Error::Regex(err) => Display::fmt(err, f),
            Error::PasswordLength => write!(f, "error: password length"),
            Error::UnsafePassword => write!(f, "error: unsafe password"),
            Error::InexistentEncryptPassword => write!(f, "error: inexistent encrypt password"),
            Error::WrongPassword => write!(f, "error: wrong password"),
            Error::EmailFormat => write!(f, "error: email format"),
            Error::EmailLength => write!(f, "error: email length"),
        }
    }
}

impl std::error::Error for Error {}
