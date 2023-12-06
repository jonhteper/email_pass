pub mod email;
pub mod password;
pub mod password_checker;

#[cfg(test)]
#[cfg(not(feature = "legacy"))]
mod tests;
