use std::fmt::Display;

use zxcvbn::Entropy;

use crate::errors::PasswordError;

/// Abstraction to [`zxcvbn::Entropy::score`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum PasswordStrength {
    /// Equals to [`zxcvbn::Entropy::score`] = 2
    Low,
    /// Equals to [`zxcvbn::Entropy::score`] = 3
    Default,
    /// Equals to [`zxcvbn::Entropy::score`] = 4
    Hard,
}

impl PasswordStrength {
    pub fn as_u8(&self) -> u8 {
        match self {
            PasswordStrength::Low => 2,
            PasswordStrength::Default => 3,
            PasswordStrength::Hard => 4,
        }
    }
}

impl Display for PasswordStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Simplify the raw passwords checking, based in minimum length and explicit strong.
/// Use the crate [`zxcvbn`] to estimate the strong based in entropy.
#[derive(Copy, Clone)]
pub struct PasswordStrengthChecker {
    min_len: usize,
    /// Corresponds to [`zxcvbn::Entropy::score`]
    strong: PasswordStrength,
}

impl PasswordStrengthChecker {
    pub fn new() -> Self {
        Self {
            min_len: 8,
            strong: PasswordStrength::Default,
        }
    }

    pub fn min_len(mut self, min_len: usize) -> Self {
        self.min_len = min_len;
        self
    }

    pub fn strong(mut self, strong: PasswordStrength) -> Self {
        self.strong = strong;
        self
    }

    /// Check the strength of a password.
    ///
    /// # Parameters
    ///
    /// * `raw_password` - The raw password to check.
    ///
    /// # Returns
    ///
    /// * `Ok(entropy)` - If the password is strong enough.
    /// * `Error::PasswordLength` - If the password is too short.
    /// * `Error::UnsafePassword` - If the password is not strong enough.
    pub fn check(&self, raw_password: &str) -> Result<Entropy, PasswordError> {
        // Check the length of the password
        if raw_password.len() < self.min_len {
            return Err(PasswordError::InvalidLength(self.min_len as u8));
        }

        // Calculate the password strength using zxcvbn
        let entropy = zxcvbn::zxcvbn(raw_password, &[])?;

        // Check if the password is strong enough
        if entropy.score() < self.strong.as_u8() {
            return Err(PasswordError::UnsafePassword(self.strong));
        }

        Ok(entropy)
    }
}

impl Default for PasswordStrengthChecker {
    fn default() -> Self {
        Self::new()
    }
}
