use bcrypt::{hash, verify, BcryptError, DEFAULT_COST};
use non_empty_string::NonEmptyString;
use regex::Regex;
use std::fmt::{Display, Formatter};
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
            Error::Bcrypt(err) => write!(f, "Bcrypt Error: {err}"),
            Error::Zxcvbn(err) => write!(f, "Zxcvbn Error: {err}"),
            Error::Regex(err) => write!(f, "Regex Error: {err}"),
            _ => write!(f, "{self}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Password {
    raw: Option<NonEmptyString>,
    encrypt: Option<NonEmptyString>,
}

impl Password {
    /// Create a password and encrypt this password.
    pub fn new(raw_password: NonEmptyString) -> Result<Self, Error> {
        let mut password = Self {
            raw: Some(raw_password),
            encrypt: None,
        };
        password.encrypt_password()?;
        password.raw = None;

        Ok(password)
    }

    /// Create a non encrypt password
    pub fn from_raw(raw_password: NonEmptyString) -> Self {
        Self {
            raw: Some(raw_password),
            encrypt: None,
        }
    }

    /// Create an encrypt password. This function not check the password's security
    pub fn from_encrypt(encrypt_password: NonEmptyString) -> Self {
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
        self.encrypt = Some(NonEmptyString::try_from(encrypt_password).unwrap());

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

    /// Return stringify
    pub fn maybe_string(&self) -> Option<String> {
        self.encrypt.as_ref().map(|password| password.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(String);

impl Email {
    pub fn new(email: &str) -> Result<Self, Error> {
        if email.len() < 6 || email.len() > 254 {
            return Err(Error::EmailLength);
        }
        let email_regex = Regex::new(
            r"^([a-z\d_+]([a-z\d_+.]*[a-z\d_+])?)@([a-z\d]+([\-.][a-z\d]+)*\.[a-z]{2,6})",
        )?;
        if !email_regex.is_match(email) {
            return Err(Error::EmailFormat);
        }

        Ok(Self(email.to_string()))
    }
}

impl Display for Email {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_email() {
        let correct_email = Email::new("example@example.com");
        let incorrect_email = Email::new("example.com");
        assert!(correct_email.is_ok());
        assert!(incorrect_email.is_err());
    }

    #[test]
    fn new_password() {
        let unsafe_password = Password::new(NonEmptyString::try_from("01234").unwrap());
        let safe_password = Password::new(
            NonEmptyString::try_from("ThisIsAPassPhrase.An.Secure.Password").unwrap(),
        );

        assert!(unsafe_password.is_err());
        assert!(safe_password.is_ok());
    }
}
