use crate::errors::Error;

/// Abstraction to [`zxcvbn::Entropy::score`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum PasswordStrong {
    /// Equals to [`zxcvbn::Entropy::score`] = 2
    Low,
    /// Equals to [`zxcvbn::Entropy::score`] = 3
    Default,
    /// Equals to [`zxcvbn::Entropy::score`] = 4
    Hard,
}

impl PasswordStrong {
    pub fn as_u8(&self) -> u8 {
        match self {
            PasswordStrong::Low => 2,
            PasswordStrong::Default => 3,
            PasswordStrong::Hard => 4,
        }
    }
}

/// Simplify the raw passwords checking, based in minimum length and explicit strong.
/// Use the crate [`zxcvbn`] to estimate the strong based in entropy.
#[derive(Copy, Clone)]
pub struct PasswordStrongChecker {
    min_len: usize,
    /// Corresponds to [`zxcvbn::Entropy::score`]
    strong: PasswordStrong,
}

impl PasswordStrongChecker {
    pub fn new() -> Self {
        Self {
            min_len: 8,
            strong: PasswordStrong::Default,
        }
    }

    pub fn min_len(mut self, min_len: usize) -> Self {
        self.min_len = min_len;
        self
    }

    pub fn strong(mut self, strong: PasswordStrong) -> Self {
        self.strong = strong;
        self
    }

    /// check the password's strong.
    pub fn check(&self, raw_password: &str) -> Result<(), Error> {
        if raw_password.len() < self.min_len {
            return Err(Error::PasswordLength);
        }

        let estimate = zxcvbn::zxcvbn(raw_password, &[])?;
        if estimate.score() < self.strong.as_u8() {
            return Err(Error::UnsafePassword);
        }

        Ok(())
    }
}

impl Default for PasswordStrongChecker {
    fn default() -> Self {
        Self::new()
    }
}
