use serde::{
    de::{Error, Unexpected, Visitor},
    Deserialize, Serialize,
};

use crate::{Password, Raw};

impl Serialize for Password {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_ref())
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
        Password::from_encrypt(str).map_err(|_| Error::invalid_value(Unexpected::Str(str), &self))
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
