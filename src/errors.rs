use std::fmt::Debug;
use thiserror::Error;
use zxcvbn::ZxcvbnError;

#[cfg(not(feature = "legacy"))]
use crate::typed::password_checker::PasswordStrength;

#[derive(Debug, Copy, Clone, Error, PartialEq, Eq)]
pub enum EmailError {
    #[error("invalid email format")]
    Format,

    #[error("invalid email length, use a value between 6 and 254 characters")]
    Length,

    #[error("invalid email domain format")]
    Domain,

    #[error("invalid email username format")]
    Username,
}

#[derive(Copy, Clone, Debug, Error, PartialEq, Eq)]
pub enum PasswordError {
    #[error("invalid password length, use a value with at least {0} characters")]
    InvalidLength(u8),

    #[error("a blank password is an invalid password")]
    BlankPassword,

    /// Replace of [`ZxcvbnError::DurationOutOfRange`].
    ///
    /// `Zxcvbn` calculate the duration since the Unix epoch to calculate
    /// the time it took to guess the password. If the calculation fails,
    /// return the error [`ZxcvbnError::DurationOutOfRange`].
    #[error("error calculating password entropy")]
    PasswordEntropy,

    #[cfg(not(feature = "legacy"))]
    #[error("the password is not strong enough, expected password with {0} strength")]
    UnsafePassword(PasswordStrength),

    #[cfg(feature = "legacy")]
    #[error("the password is not strong enough")]
    NotEnoughStrongPassword,

    #[error("the password provided is not encrypted")]
    PasswordNotEncrypted,

    #[cfg(feature = "legacy")]
    #[error("error encrypting password")]
    PasswordEncryption,

    #[cfg(feature = "legacy")]
    #[error("error during verification procress")]
    PasswordVerification,

    #[cfg(feature = "legacy")]
    #[error("the raw password don't match with encrypted")]
    WrongPassword,
}

impl From<ZxcvbnError> for PasswordError {
    fn from(err: ZxcvbnError) -> Self {
        match err {
            ZxcvbnError::BlankPassword => Self::BlankPassword,
            ZxcvbnError::DurationOutOfRange => Self::PasswordEntropy,
        }
    }
}
