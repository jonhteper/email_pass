#![allow(unused)]

use std::str::FromStr;

use bcrypt::{BcryptError, DEFAULT_COST};

use crate::{Email, Password};

use super::password::Encrypt;

const SECURE_PASSWORD_VALUE: &str = "ThisIsAPassPhrase.And.Secure.Password";

#[test]
fn safe_password_works() {
    let encrypt_password = Password::new(SECURE_PASSWORD_VALUE)
        .check()
        .expect("error with password strength")
        .to_encrypt(DEFAULT_COST)
        .expect("error encrypting password");

    let password = Password::from_encrypt(encrypt_password.as_str());
    assert!(password.is_ok());
    println!("{}", password.unwrap());
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

#[test]
fn typed_email_constructor_works() {
    let email = Email::build("john", "example.com").expect("Error creating a email");
    assert_eq!(email.username(), "john");
    assert_eq!(email.domain(), "example.com");

    let str_email = "john@example.com";
    let new_email = Email::from_str(str_email).expect("Error with string email");

    assert_eq!(&email, &new_email);
    assert_eq!(email.to_string().as_str(), str_email);
}
