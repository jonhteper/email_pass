use crate::errors::EmailError;

use once_cell::sync::Lazy;
use regex::Regex;

use std::fmt::{Display, Formatter};
use std::ops::Deref;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?P<local>[a-zA-Z0-9_.+-]+)@(?P<domain>[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)").unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
#[cfg_attr(feature = "serde", serde(into = "String"))]
pub struct Email(String);

impl Email {
    pub fn new(email: &str) -> Result<Self, EmailError> {
        if !(6..=254).contains(&email.len()) {
            return Err(EmailError::Length);
        }

        if !EMAIL_REGEX.is_match(email) {
            return Err(EmailError::Format);
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

impl TryFrom<String> for Email {
    type Error = EmailError;

    fn try_from(email: String) -> Result<Self, Self::Error> {
        Self::new(&email)
    }
}

impl From<Email> for String {
    fn from(email: Email) -> Self {
        email.to_string()
    }
}
