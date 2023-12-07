pub mod email;
pub mod password;
pub mod password_checker;

#[cfg(feature = "serde")]
pub mod serde_feature;

#[cfg(test)]
#[cfg(not(feature = "legacy"))]
mod tests;
