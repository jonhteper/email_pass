use crate::errors::Error;
use regex::Regex;
use std::fmt::{Display, Formatter};
use std::ops::Deref;

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
