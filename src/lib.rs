use bcrypt::{hash, verify, BcryptError, DEFAULT_COST};
use regex::Regex;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;
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
            Error::PasswordLength => write!(f, "Error: Password Length"),
            Error::UnsafePassword => write!(f, "Error: Unsafe Password"),
            Error::InexistentEncryptPassword => write!(f, "Error: Inexistent Encrypt Password"),
            Error::WrongPassword => write!(f, "Error: Wrong Password"),
            Error::EmailFormat => write!(f, "Error: Email Format"),
            Error::EmailLength => write!(f, "Error: Email Length"),
        }
    }
}

impl std::error::Error for Error {}

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

impl Deref for Email {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_constructor_works() {
        let correct_email = Email::new("example@example.com");
        let incorrect_email = Email::new("example.com");
        assert!(correct_email.is_ok());
        assert!(incorrect_email.is_err());
    }

    #[test]
    fn password_constructor_works() {
        let unsafe_password = Password::new("01234".to_string());
        let safe_password = Password::new("ThisIsAPassPhrase.An.Secure.Password".to_string());

        assert!(unsafe_password.is_err());
        assert!(safe_password.is_ok());
    }

    #[test]
    fn password_safe_debug_works() {
        let safe_password = Password::from_raw("ThisIsAPassPhrase.An.Secure.Password".to_string());
        let str_password = format!("{:?}", &safe_password);
        assert!(!str_password.contains("ThisIs"))
    }
}
