use std::{
    fmt::{Display, Formatter},
    str::FromStr,
    sync::Arc,
};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::errors::EmailError;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?P<local>[a-zA-Z0-9_.+-]+)@(?P<domain>[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)").unwrap()
});

static EMAIL_USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"([a-zA-Z0-9_.+-]+)").unwrap());
static EMAIL_DOMAIN_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)").unwrap());

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
#[cfg_attr(feature = "serde", serde(into = "String"))]
pub struct Email {
    local: Arc<str>,
    domain: Arc<str>,
}

impl Email {
    #[inline]
    fn check_len(len: usize) -> Result<(), EmailError> {
        if !(6..=254).contains(&len) {
            Err(EmailError::Length)?
        }

        Ok(())
    }

    #[inline]
    fn check_username(username: &str) -> Result<(), EmailError> {
        if !EMAIL_USERNAME_REGEX.is_match(username) {
            Err(EmailError::Username)?
        }

        Ok(())
    }

    #[inline]
    fn check_domain(domain: &str) -> Result<(), EmailError> {
        if !EMAIL_DOMAIN_REGEX.is_match(domain) {
            Err(EmailError::Domain)?
        }

        Ok(())
    }

    /// Creates a new [`Email`] instance.
    ///
    /// # Parameters
    ///
    /// * `username` - The username of the email address.
    /// * `domain` - The domain of the email address.
    ///
    /// # Returns
    ///
    /// Returns a [`Result`] with a [`EmailError`] if the username or domain is not valid.
    ///
    pub fn build(username: &str, domain: &str) -> Result<Self, EmailError> {
        Self::check_len(username.len() + domain.len())?;
        Self::check_username(username)?;
        Self::check_domain(domain)?;

        Ok(Self {
            local: Arc::from(username),
            domain: Arc::from(domain),
        })
    }

    #[inline]
    pub fn username(&self) -> &str {
        &self.local
    }

    #[inline]
    pub fn local(&self) -> &str {
        &self.local
    }

    #[inline]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Sets the username of the email address.
    ///
    /// # Parameters
    ///
    /// * `username` - The new username of the email address.
    ///
    /// # Returns
    ///
    /// Returns a [`Result`] with a [`EmailError`] if the username is not valid.
    ///
    pub fn set_username(&mut self, username: &str) -> Result<(), EmailError> {
        Self::check_username(username)?;

        self.local = Arc::from(username);

        Ok(())
    }

    /// Sets the domain of the email address.
    ///
    /// # Parameters
    ///
    /// * `domain` - The new domain of the email address.
    ///
    /// # Returns
    ///
    /// Returns a [`Result`] with a [`EmailError`] if the domain is not valid.
    ///
    pub fn set_domain(&mut self, domain: &str) -> Result<(), EmailError> {
        Self::check_domain(domain)?;

        self.domain = Arc::from(domain);

        Ok(())
    }
}

impl FromStr for Email {
    type Err = EmailError;

    fn from_str(email: &str) -> Result<Self, Self::Err> {
        Self::check_len(email.len())?;

        let captures = EMAIL_REGEX.captures(email).ok_or(EmailError::Format)?;
        let local = captures.name("local").unwrap().as_str();
        let domain = captures.name("domain").unwrap().as_str();

        Ok(Self {
            local: Arc::from(local),
            domain: Arc::from(domain),
        })
    }
}

impl TryFrom<String> for Email {
    type Error = EmailError;

    fn try_from(email: String) -> Result<Self, Self::Error> {
        Self::from_str(&email)
    }
}

impl Display for Email {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

impl From<Email> for String {
    fn from(email: Email) -> Self {
        email.to_string()
    }
}
