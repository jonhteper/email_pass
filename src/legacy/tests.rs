#![allow(unused)]

use std::str::FromStr;

use bcrypt::{BcryptError, DEFAULT_COST};

use crate::Email;
use crate::Password;

const SECURE_PASSWORD_VALUE: &str = "ThisIsAPassPhrase.And.Secure.Password";

#[test]
fn email_constructor_works() {
    let correct_email = Email::new("example@example.com");
    let incorrect_email = Email::new("example.com");
    assert!(correct_email.is_ok());
    assert!(incorrect_email.is_err());
}

#[test]
fn legacy_password_constructor_works() {
    let unsafe_password = Password::new("01234".to_string());
    let safe_password = Password::new(SECURE_PASSWORD_VALUE.to_string());

    assert!(unsafe_password.is_err());
    assert!(safe_password.is_ok());
}

#[test]
fn legacy_password_safe_debug_works() {
    let safe_password = Password::from_raw(SECURE_PASSWORD_VALUE.to_string());
    let str_password = format!("{:?}", &safe_password);
    assert!(!str_password.contains("ThisIs"))
}
