use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::ops::Deref;
use bcrypt::{DEFAULT_COST, hash};
use regex::Regex;
use crate::Error;

pub struct Raw;
pub struct Encrypt;

#[derive(Clone, Eq, PartialEq)]
pub struct Password<State = Encrypt> {
    value: String,
    state: PhantomData<State>
}

impl Password {
    pub fn new(raw_password: &str) -> Password<Raw> {
        Password {
            value: raw_password.to_owned(),
            state: PhantomData,
        }
    }

    pub fn from_raw(raw_password: &str) -> Password<Raw> {
        Self::new(raw_password)
    }

    pub fn from_encrypt(encrypted_password: &str) -> Result<Password<Encrypt>, Error> {
        let password_regex = Regex::new(r"^\$([a-z\d]+)\$([a-z\d]+)\$.*")?;
        if !password_regex.is_match(encrypted_password) {
            return Err(Error::InexistentEncryptPassword)
        }

        Ok(Password {
            value: encrypted_password.to_owned(),
            state: PhantomData,
        })
    }

    fn check_password(raw_password: &str) -> Result<(), Error> {
        if raw_password.len() < 8 {
            return Err(Error::PasswordLength);
        }

        let estimate = zxcvbn::zxcvbn(raw_password, &[])?;
        if estimate.score() < 4 {
            return Err(Error::UnsafePassword);
        }

        Ok(())
    }

    fn encrypt_password(raw_password: &str) ->Result<String, Error> {
        Ok(hash(raw_password, DEFAULT_COST + 1)?)

    }
}

impl Password<Raw> {
    pub fn check(self)->Result<Self, Error> {
        Password::check_password(&self.value)?;
        Ok(self)
    }


    /// Transforms [`Password<Raw>`] to [`Password<Encrypt>`], just encrypting the inner value.
    /// This method not checks the password's strong.
    pub fn to_encrypt(self) -> Result<Password<Encrypt>, Error> {
        let encrypt_password = Password::encrypt_password(&self.value)?;
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

impl Into<String> for Password<Encrypt> {
    fn into(self) -> String {
        self.value
    }
}

impl Deref for Password<Encrypt> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}


