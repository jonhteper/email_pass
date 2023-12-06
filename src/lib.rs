pub mod errors;

#[cfg(feature = "legacy")]
mod legacy;

#[cfg(not(feature = "legacy"))]
mod typed;

#[cfg(feature = "legacy")]
pub use legacy::{email::Email, password::Password};

#[cfg(not(feature = "legacy"))]
pub use typed::{
    email::Email,
    password::{Encrypt, Password, Raw},
    password_checker::{PasswordStrength, PasswordStrengthChecker},
};

pub use errors::{EmailError, PasswordError};
