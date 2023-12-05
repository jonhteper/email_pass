use std::fmt::Debug;
use thiserror::Error;
use zxcvbn::ZxcvbnError;

use crate::password::checker::PasswordStrength;

#[derive(Debug, Copy, Clone, Error, PartialEq, Eq)]
pub enum EmailError {
    #[error("invalid email format")]
    InvalidFormat,

    #[error("invalid email length, use a value between 6 and 254 characters")]
    InvalidLength,

    #[error("invalid email domain format")]
    InvalidDomain,

    #[error("invalid email username format")]
    InvalidUsername,
}

#[derive(Debug, Error, PartialEq, Eq)]
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

    #[error("the password is not strong enough, expected password with {0} strength")]
    UnsafePassword(PasswordStrength),

    #[error("the password provided is not encrypted")]
    PasswordNotEncrypted,
}

impl From<ZxcvbnError> for PasswordError {
    fn from(err: ZxcvbnError) -> Self {
        match err {
            ZxcvbnError::BlankPassword => Self::BlankPassword,
            ZxcvbnError::DurationOutOfRange => Self::PasswordEntropy,
        }
    }
}
