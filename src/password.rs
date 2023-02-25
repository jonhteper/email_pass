pub mod legacy;
pub mod safe;
pub mod checker;

#[cfg(feature = "legacy")]
pub use legacy::Password;

#[cfg(not(feature = "legacy"))]
pub use safe::Password;
