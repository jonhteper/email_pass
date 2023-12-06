# email_pass

[![Crates.io](https://shields.io/crates/v/email_pass.svg)](https://crates.io/crates/email_pass)

`Email` and `Password` types in Rust.

## Email data type

```rust
use email_pass::Email;
fn main() {
    let email1 = Email::build("john", "example.com").expect("Error creating a email");
    
    let email2 = Email::from_str("john@example.com").expect("Error with string email");

    assert_eq!(&email1, &email2);

    assert_eq!(email2.username(), "john");
    assert_eq!(email2.domain(), "example.com");
}
```

## Password data type

The type `Password` differentiates the raw password from encrypted passwords and provides only the correct methods for each. 

```rust
use email_pass::Password;
fn main() -> Result<(), Error> {
    let encrypt_password = Password::new("ThisIsAPassPhrase.And.Secure.Password")
        .check()? // raw password method
        .to_encrypt_default()?; // raw password method
    
    // encrypted passwords implements the Deref trait
    let password = Password::from_encrypt(encrypt_password.as_str())?;
    
    println!("{}", password);

    Ok(())
}
```
The next code don't compile, because the raw passwords do not implement either the Display trait or the Debug trait. 
```rust
use email_pass::Password;
fn main() {
    let password = Password::new("ThisIsAPassPhrase.And.Secure.Password");
    println!("{}", &password); // ❌
    println!("{:?}", &password); // ❌ 
}
```
## Legacy Password and Email types
You can use the old types behind the `legacy` feature.
```toml
email_pass = { version = "0.7.0", features = ["legacy"] }
```

### Password
```rust
use email_pass::Password;
fn main() {
    let unsafe_password = Password::new("01234".to_string());
    let safe_password = Password::new(
        "ThisIsAPassPhrase.And.Secure.Password".to_string(),
    );

    assert!(unsafe_password.is_err());
    assert!(safe_password.is_ok());
}
```

If the password is not encrypted, you can't access the inner value.
```rust 
use email_pass::password::legacy::Password;
fn main() {
    let mut password = Password::from_raw(
        "ThisIsAPassPhrase.And.Secure.Password".to_string(),
    );
    assert!(password.try_to_str().is_err());

    password.encrypt_password().expect("Error encrypting password");
    assert!(password.try_to_str().is_ok());
}
```

The `Password` type implements the `Debug` trait securely.
```rust
fn main(){
    let safe_password = Password::from_raw("ThisIsAPassPhrase.And.Secure.Password".to_string());
    let str_password = format!("{:?}", &safe_password);
    assert!(!str_password.contains("ThisIs"))
}
```

### Email
You can construct the `Email` with the `new` method.
```rust
fn main(){
    let correct_email = Email::new("example@example.com");
    let incorrect_email = Email::new("example.com");
    assert!(correct_email.is_ok());
    assert!(incorrect_email.is_err());
}
```

## Serde Suport

The types `Email` and `Password` implements the traits `Serialize` and `Deserialize` in the feature `serde`. 

```toml
[dependencies]
email_pass = { version = "0.7.0", features = ["serde"] }
```



## Migration from version 0.4.1 to version <= 0.7.0

If you don't want break your code, just use the feature `legacy`:
```toml
[dependencies]
email_pass = { version = "0.7.0", features = ["legacy"] }
```
Then, you can try the new Password type with the import:
```rust
use email_pass::password::safe::Password;
```

## Migration from version 0.4.1 to version 0.8.0+
Your code must have been broken when upgrading, because the `v0.8.0` 
uses a new errors API, and uses a new Email constructors.
To fix your code: 
* Adapt your error types to migrate to the new version.
* Replace all uses of `Deref` trait with `Password` type.
* Replace all uses of `Email::new` method with `Email::build` or `Email::from_str`.


## Migration from version 0.7.0 to version 0.8.0+
Same case as [above](#migration-from-version-041-to-version-080). But if you use have been using both `safe` and `legacy` password types, you should choose only one.


## Acknowledgments

Thanks to [letsgetrusty](https://github.com/letsgetrusty/) for the 
[repo that inspired](https://github.com/letsgetrusty/generics_and_zero_sized_types) the `Password` type.
