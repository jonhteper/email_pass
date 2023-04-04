#![allow(unused)]

use bcrypt::DEFAULT_COST;

use super::*;
use crate::errors::Error;
use crate::password::legacy;
use crate::password::safe::{Encrypt, Password};
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
    let unsafe_password = legacy::Password::new("01234".to_string());
    let safe_password = legacy::Password::new(SECURE_PASSWORD_VALUE.to_string());

    assert!(unsafe_password.is_err());
    assert!(safe_password.is_ok());
}

#[test]
fn legacy_password_safe_debug_works() {
    let safe_password = legacy::Password::from_raw(SECURE_PASSWORD_VALUE.to_string());
    let str_password = format!("{:?}", &safe_password);
    assert!(!str_password.contains("ThisIs"))
}

#[test]
fn safe_password_works() -> Result<(), Error> {
    let encrypt_password = Password::new(SECURE_PASSWORD_VALUE)
        .check()?
        .to_encrypt(DEFAULT_COST)?;

    let password = Password::from_encrypt(&encrypt_password);
    assert!(password.is_ok());
    println!("{}", password.unwrap());

    Ok(())
}

#[test]
fn safe_password_constructor_works() {
    let password = Password::from_encrypt(SECURE_PASSWORD_VALUE);
    assert!(password.is_err())
}

fn create_password(password: &str) -> Password {
    Password::new("my.new.password.1")
        .check()
        .expect("unsafe password")
        .to_encrypt(DEFAULT_COST)
        .expect("error encripting password")
}

#[derive(Debug, Clone)]
struct User<'a> {
    id: &'a str,
    password: Password<Encrypt>,
}

impl<'a> User<'a> {
    pub fn new(id: &'a str, password: Password) -> Self {
        Self { id, password }
    }

    pub fn change_password(&mut self, password: &str) {
        let new_password = create_password(password);
        self.password = new_password;
    }
}

#[test]
fn password_in_struct() {
    let id = "id.user.example";
    let password = create_password("my.new.password.1");
    let mut user = User::new(id, password);
    user.change_password(SECURE_PASSWORD_VALUE);

    println!("{:?}", user);
}

#[test]
fn password_hash_works() {
    let raw_password = Password::from_raw(SECURE_PASSWORD_VALUE);
    let encrypt_password = raw_password
        .clone()
        .check()
        .unwrap()
        .to_encrypt(DEFAULT_COST)
        .unwrap();
    assert!(encrypt_password.verify(&raw_password).unwrap())
}
