#![allow(unused)]

use std::str::FromStr;

use bcrypt::{BcryptError, DEFAULT_COST};

use crate::{Email, Encrypt, Password};

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

#[derive(Debug, Clone, Eq, PartialEq)]
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

#[cfg(feature = "serde")]
mod serde_tests {
    use crate::{Email, Password, Raw};
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::str::FromStr;

    const GENERIC_HASH: &'static str = "$2b$04$teRReyH3sVfCd8JA71Sm6xekdy6KhRIzYYERUEUC";
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct User {
        pub email: Email,
        pub password: Password,
    }

    #[test]
    fn serialize_works() {
        let user = User {
            email: Email::from_str("mail@mail.com").unwrap(),
            password: Password::from_encrypt(GENERIC_HASH).unwrap(),
        };

        let result = serde_json::to_string(&user);
        assert!(result.is_ok());
        println!("{:?}", result.unwrap());
    }

    #[test]
    fn deserialize_works() {
        let user_json = json!({
            "email": "mail@mail.com",
            "password": GENERIC_HASH,
        });

        let user = User {
            email: Email::from_str("mail@mail.com").unwrap(),
            password: Password::from_encrypt(GENERIC_HASH).unwrap(),
        };

        let deserialize_user = serde_json::from_value::<User>(user_json).unwrap();

        assert_eq!(&deserialize_user, &user);
        println!("{:?}", &deserialize_user);
    }

    #[test]
    fn deserialize_fails_correctly() {
        let bad_values = [
            json!({
                "email": "mail.com",
                "password": GENERIC_HASH,
            }),
            json!({
                "email": "mail@mail.com",
                "password": "0123456789",
            }),
        ];

        for value in bad_values {
            serde_json::from_value::<User>(value).expect_err("deserialize must fail");
        }
    }

    #[derive(Deserialize, PartialEq)]
    struct UserRequest {
        pub name: String,
        pub password: Password<Raw>,
    }

    #[test]
    fn deserialize_raw_works<'a>() {
        let user_json = json!({
            "name": "John Doe",
            "password": "0123456789"
        });

        let user = UserRequest {
            name: "John Doe".to_string(),
            password: Password::new("0123456789"),
        };

        let deserialize_user = serde_json::from_value::<UserRequest>(user_json).unwrap();

        assert!(deserialize_user == user);
    }

    #[test]
    fn deserialize_raw_fails_correctly() {
        let bad_input = json!({
            "name": "John Doe",
            "password": ""
        });

        let result = serde_json::from_value::<UserRequest>(bad_input);
        assert!(result.is_err())
    }
}
