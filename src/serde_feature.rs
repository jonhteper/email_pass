use serde::{
    de::{Error, Unexpected, Visitor},
    Deserialize, Serialize,
};

use crate::Email;

impl Serialize for Email {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self)
    }
}

pub struct EmailVisitor;

impl<'de> Visitor<'de> for EmailVisitor {
    type Value = Email;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string whith an email structure")
    }

    fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Email::new(str).map_err(|_| Error::invalid_value(Unexpected::Str(str), &self))
    }

    fn visit_string<E>(self, str: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_str(&str)
    }
}

impl<'de> Deserialize<'de> for Email {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(EmailVisitor)
    }
}

#[cfg(not(feature = "legacy"))]
pub mod safe_password {
    use serde::{
        de::{Error, Unexpected, Visitor},
        Deserialize, Serialize,
    };

    use crate::{password::safe::Raw, Password};

    impl Serialize for Password {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&self)
        }
    }

    pub struct EncryptPasswordVisitor;

    impl<'de> Visitor<'de> for EncryptPasswordVisitor {
        type Value = Password;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an hashed string")
        }

        fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Password::from_encrypt(str)
                .map_err(|_| Error::invalid_value(Unexpected::Str(str), &self))
        }

        fn visit_string<E>(self, str: String) -> Result<Self::Value, E>
        where
            E: Error,
        {
            self.visit_str(&str)
        }
    }

    impl<'de> Deserialize<'de> for Password {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_str(EncryptPasswordVisitor)
        }
    }

    pub struct RawPasswordVisitor;

    impl<'de> Visitor<'de> for RawPasswordVisitor {
        type Value = Password<Raw>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an unencrypted string of at least 1 character in length")
        }

        fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            if str.is_empty() {
                return Err(Error::invalid_length(0, &self));
            }

            Ok(Password::new(str))
        }

        fn visit_string<E>(self, str: String) -> Result<Self::Value, E>
        where
            E: Error,
        {
            self.visit_str(&str)
        }
    }

    impl<'de> Deserialize<'de> for Password<Raw> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_str(RawPasswordVisitor)
        }
    }
}

#[cfg(not(feature = "legacy"))]
#[cfg(test)]
mod serde_tests {
    use crate::{password::safe::Raw, Email, Password};
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    const GENERIC_HASH: &'static str = "$2b$04$teRReyH3sVfCd8JA71Sm6xekdy6KhRIzYYERUEUC";
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct User {
        pub email: Email,
        pub password: Password,
    }

    #[test]
    fn serialize_works() {
        let user = User {
            email: Email::new("mail@mail.com").unwrap(),
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
            email: Email::new("mail@mail.com").unwrap(),
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
