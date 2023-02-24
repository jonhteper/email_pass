# email_pass
Email and Password Type in Rust

## Safe Email Constructor

```rust
use email_pass::Email;
fn main() {
    let correct_email = Email::new("example@example.com");
    let incorrect_email = Email::new("example.com");
    assert!(correct_email.is_ok());
    assert!(incorrect_email.is_err());
}
 ```

### Safe Password Type
The type `Password` differentiates the raw password from encrypted passwords 
and provides only the correct methods for each. 
```rust
use email_pass::Password;
fn main() -> Result<(), Error> {
    let encrypt_password = password::Password::new("ThisIsAPassPhrase.And.Secure.Password")
        .check()? // raw password method
        .to_encrypt()?; // raw password method
    
    // encrypted passwords implements the Deref trait
    let password = password::Password::from_encrypt(&encrypt_password)?;
    
    println!("{}", password);

    Ok(())
}
```
The next code don't compile, because the raw passwords do not implement either the Display trait or the Debug trait. 
```rust
use email_pass::Password;
fn main() {
    let password = password::Password::new("ThisIsAPassPhrase.And.Secure.Password");
    println!("{}", &password); // ❌
    println!("{:?}", &password); // ❌ 
}
```
## Legacy Safe Passwords Constructor
*WARNING: This type is until available in [password/legacy.rs](./src/password/legacy.rs). The feature `legacy` only modifies the access of type*.

```rust
use email_pass::password::legacy::Password;
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
    assert_eq!(password.try_to_str(), Err(Error::InexistentEncryptPassword));

    password.encrypt_password().unwrap();
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

### Migration from v0.4.1 to v0.5.0
If you don't want break your code, just use the featue `legacy`:
```toml
[dependencies]
email_pass = { version = "0.5.0", features = ["legacy"] }
```
Then, you can try the new Password type with the import:
```rust
use email_pass::password::safe::Password;
```


### Acknowledgments
Thanks to [letsgetrusty](https://github.com/letsgetrusty/) for the 
[repo that inspired](https://github.com/letsgetrusty/generics_and_zero_sized_types) the `Password` type.