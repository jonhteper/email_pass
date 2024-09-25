use crate::errors::PasswordError;
use crate::typed::password_checker::PasswordStrengthChecker;
use bcrypt::{hash, verify, BcryptError};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::sync::Arc;

pub const HASHED_PASSWORD_REGEX_VALUE: &str = r"^\$([a-z\d]+)\$([a-z\d]+)\$.*";

static HASHED_PASSWORD_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(HASHED_PASSWORD_REGEX_VALUE).unwrap());

#[derive(Clone, Eq, PartialEq)]
pub struct Raw;
#[derive(Clone, Eq, PartialEq)]
pub struct Encrypt;

/// Safe-access password abstraction.
#[derive(Clone, Eq, PartialEq)]
pub struct Password<State = Encrypt> {
    value: Arc<str>,
    state: PhantomData<State>,
}

impl Password {
    pub fn new(raw_password: &str) -> Password<Raw> {
        Password {
            value: Arc::from(raw_password),
            state: PhantomData,
        }
    }

    /// Create a non encrypt password.
    pub fn from_raw(raw_password: &str) -> Password<Raw> {
        Self::new(raw_password)
    }

    /// Create an encrypt password, check if password is really hashed.
    pub fn from_encrypt(encrypted_password: &str) -> Result<Password<Encrypt>, PasswordError> {
        if !HASHED_PASSWORD_REGEX.is_match(encrypted_password) {
            Err(PasswordError::PasswordNotEncrypted)?
        }

        Ok(Password {
            value: Arc::from(encrypted_password),
            state: PhantomData,
        })
    }

    pub fn verify(&self, raw_password: &Password<Raw>) -> Result<bool, BcryptError> {
        let raw_password: &str = &raw_password.value;
        verify(raw_password, &self.value)
    }

    pub fn verify_from_raw<R: AsRef<str>>(&self, raw: R) -> Result<bool, BcryptError> {
        verify(raw.as_ref(), &self.value)
    }

    /// Extracts the inner value from [`Password<Encrypt>`].
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl Password<Raw> {
    /// Check the password's strong, use [`PasswordStrengthChecker`] with default values.
    /// If you want change this values, use [`Password<Raw>::custom_check`].
    pub fn check(self) -> Result<Self, PasswordError> {
        PasswordStrengthChecker::new().check(&self.value)?;
        Ok(self)
    }

    /// Check the password's strong
    /// # Examples
    /// Hard strong password example:
    ///```
    /// use email_pass::{Password, PasswordStrengthChecker, PasswordStrength};
    ///
    /// let checker = PasswordStrengthChecker::new()
    ///         .min_len(20)
    ///         .strong(PasswordStrength::Hard);
    ///
    /// let password_err = Password::new("my.passphrase.0-9").custom_check(checker);
    /// assert!(password_err.is_err());
    /// ```
    /// Low strong password example:
    ///```
    /// use email_pass::{Password, PasswordStrengthChecker, PasswordStrength};
    ///
    /// let checker = PasswordStrengthChecker::new()
    ///         .min_len(8)
    ///         .strong(PasswordStrength::Low);
    ///
    /// let raw_password = Password::new("1234567azhc").custom_check(checker);
    /// assert!(raw_password.is_ok());
    /// ```
    pub fn custom_check(self, checker: PasswordStrengthChecker) -> Result<Self, PasswordError> {
        checker.check(&self.value)?;
        Ok(self)
    }

    /// Transforms [`Password<Raw>`] to [`Password<Encrypt>`], encrypting the inner value based in a cost value.
    /// This method not checks the password's strong.
    pub fn to_encrypt(self, cost: u32) -> Result<Password<Encrypt>, BcryptError> {
        let str_password: &str = &self.value;
        let encrypt_password = hash(str_password, cost)?;

        Ok(Password {
            value: Arc::from(encrypt_password),
            state: PhantomData,
        })
    }

    /// Transforms [`Password<Raw>`] to [`Password<Encrypt>`], just encrypting the inner value.
    /// This method not checks the password's strong.
    pub fn to_encrypt_default(self) -> Result<Password<Encrypt>, BcryptError> {
        self.to_encrypt(bcrypt::DEFAULT_COST)
    }

    /// Transforms [`Password<Raw>`] to [`Password<Encrypt>`], encrypting the inner value based in a cost value.
    /// This method not checks the password's strong.
    #[inline]
    pub fn to_encrypt_with_cost(self, cost: u32) -> Result<Password<Encrypt>, BcryptError> {
        Self::to_encrypt(self, cost)
    }
}

impl From<Arc<str>> for Password<Raw> {
    fn from(value: Arc<str>) -> Self {
        Password {
            value,
            state: PhantomData,
        }
    }
}

impl Display for Password<Encrypt> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.value, f)
    }
}

impl AsRef<str> for Password<Encrypt> {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

impl AsRef<str> for Password<Raw> {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

impl Debug for Password<Encrypt> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Password(\"{}\")", self.as_ref())
    }
}
