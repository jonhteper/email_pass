pub mod legacy;
pub mod safe;

#[cfg(feature = "legacy")]
pub use legacy::Password;

#[cfg(not(feature = "legacy"))]
pub use safe::Password;
