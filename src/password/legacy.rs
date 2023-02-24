use crate::errors::Error;
use bcrypt::{hash, verify, DEFAULT_COST};
use std::fmt::{Debug, Formatter};

#[derive(Clone, PartialEq, Eq)]
pub struct Password {
    raw: Option<String>,
    encrypt: Option<String>,
}

impl Password {
    /// Create a password and encrypt this password.
    pub fn new(raw_password: String) -> Result<Self, Error> {
        let mut password = Self {
            raw: Some(raw_password),
            encrypt: None,
        };
        password.encrypt_password()?;
        password.raw = None;

        Ok(password)
    }

    /// Create a non encrypt password
    pub fn from_raw(raw_password: String) -> Self {
        Self {
            raw: Some(raw_password),
            encrypt: None,
        }
    }

    /// Create an encrypt password. This function not check the password's security
    pub fn from_encrypt(encrypt_password: String) -> Self {
        Self {
            raw: None,
            encrypt: Some(encrypt_password),
        }
    }

    /// Encrypts a non encrypted password
    pub fn encrypt_password(&mut self) -> Result<(), Error> {
        let raw_len_err = Error::PasswordLength;

        if self.raw.is_none() {
            return Err(raw_len_err);
        }

        let raw_password: &str = self.raw.as_ref().unwrap().as_ref();
        if raw_password.len() < 8 {
            return Err(raw_len_err);
        }

        let estimate = zxcvbn::zxcvbn(raw_password, &[])?;
        if estimate.score() < 4 {
            return Err(Error::UnsafePassword);
        }
        let encrypt_password = hash(raw_password, DEFAULT_COST + 1)?;
        self.encrypt = Some(encrypt_password);

        Ok(())
    }

    /// Verify an encrypt password from non encrypt string
    pub fn check(&self, raw_password: String) -> Result<(), Error> {
        if self.encrypt.is_none() {
            return Err(Error::InexistentEncryptPassword);
        }

        if !verify(raw_password, self.encrypt.as_ref().unwrap().as_ref())? {
            return Err(Error::WrongPassword);
        }

        Ok(())
    }

    /// Return internal value, if encrypt version exists.
    pub fn maybe_string(&self) -> Option<String> {
        self.encrypt.as_ref().map(|password| password.to_string())
    }

    /// Returns a ref of the encrypt password, if exists, otherwise returns [`Error::InexistentEncryptPassword`].
    pub fn try_to_str(&self) -> Result<&String, Error> {
        self.encrypt
            .as_ref()
            .ok_or(Error::InexistentEncryptPassword)
    }

    /// Returns the encrypt password, if exists, otherwise returns [`Error::InexistentEncryptPassword`].
    ///
    /// **WARNING**: this method cloned the internal value
    pub fn try_to_string(&self) -> Result<String, Error> {
        self.encrypt.clone().ok_or(Error::InexistentEncryptPassword)
    }
}

impl TryInto<String> for Password {
    type Error = Error;

    fn try_into(self) -> Result<String, Self::Error> {
        self.encrypt.ok_or(Error::InexistentEncryptPassword)
    }
}

impl Debug for Password {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = self.encrypt.clone().unwrap_or_default();
        write!(f, "Password(\"{value}\")")
    }
}
