use crate::errors::Error;
use crate::password::checker::PasswordStrongChecker;
use bcrypt::{hash, DEFAULT_COST};
use regex::Regex;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::ops::Deref;

pub const HASHED_PASSWORD_REGEX_VALUE: &str = r"^\$([a-z\d]+)\$([a-z\d]+)\$.*";

#[derive(Clone)]
pub struct Raw;
#[derive(Clone)]
pub struct Encrypt;

/// Safe-access password abstraction.
#[derive(Clone, Eq, PartialEq)]
pub struct Password<State = Encrypt> {
    value: String,
    state: PhantomData<State>,
}

impl Password {
    pub fn new(raw_password: &str) -> Password<Raw> {
        Password {
            value: raw_password.to_owned(),
            state: PhantomData,
        }
    }

    /// Create a non encrypt password.
    pub fn from_raw(raw_password: &str) -> Password<Raw> {
        Self::new(raw_password)
    }

    /// Create an encrypt password, check if password is really hashed.
    pub fn from_encrypt(encrypted_password: &str) -> Result<Password<Encrypt>, Error> {
        let password_regex = Regex::new(HASHED_PASSWORD_REGEX_VALUE)?;
        if !password_regex.is_match(encrypted_password) {
            return Err(Error::InexistentEncryptPassword);
        }

        Ok(Password {
            value: encrypted_password.to_owned(),
            state: PhantomData,
        })
    }
}

impl Password<Raw> {
    /// Check the password's strong, use [`PasswordStrongChecker`] with default values.
    /// If you want change this values, use [`Password<Raw>::custom_check`].
    pub fn check(self) -> Result<Self, Error> {
        PasswordStrongChecker::new().check(&self.value)?;
        Ok(self)
    }

    /// Check the password's strong
    /// # Examples
    /// Hard strong password example:
    ///```
    /// use email_pass::Password;
    /// use email_pass::password::checker::{PasswordStrongChecker, PasswordStrong};
    ///
    /// let checker = PasswordStrongChecker::new()
    ///         .min_len(20)
    ///         .strong(PasswordStrong::Hard);
    ///
    /// let password_err = Password::new("my.passphrase.0-9").custom_check(checker);
    /// assert!(password_err.is_err());
    /// ```
    /// Low strong password example:
    ///```
    /// use email_pass::Password;
    /// use email_pass::password::checker::{PasswordStrongChecker, PasswordStrong};
    ///
    /// let checker = PasswordStrongChecker::new()
    ///         .min_len(8)
    ///         .strong(PasswordStrong::Low);
    ///
    /// let raw_password = Password::new("1234567azhc").custom_check(checker);
    /// assert!(raw_password.is_ok());
    /// ```
    pub fn custom_check(self, checker: PasswordStrongChecker) -> Result<Self, Error> {
        checker.check(&self.value)?;
        Ok(self)
    }

    /// Transforms [`Password<Raw>`] to [`Password<Encrypt>`], just encrypting the inner value.
    /// This method not checks the password's strong.
    pub fn to_encrypt(self) -> Result<Password<Encrypt>, Error> {
        let encrypt_password = hash(&self.value, DEFAULT_COST + 1)?;
        Ok(Password {
            value: encrypt_password,
            state: PhantomData,
        })
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

impl Debug for Password<Encrypt> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Password(\"{}\")", self.as_ref())
    }
}

impl Deref for Password<Encrypt> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
