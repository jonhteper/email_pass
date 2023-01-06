# email_pass
Email and Password Type in Rust

Include:

## Safe Email Constructor

```rust
fn main() {
    let correct_email = Email::new("example@example.com");
    let incorrect_email = Email::new("example.com");
    assert!(correct_email.is_ok());
    assert!(incorrect_email.is_err());
}
 ```

## Safe Passwords Constructor

```rust
fn main() {
    let unsafe_password = Password::new("01234".to_string());
    let safe_password = Password::new(
        "ThisIsAPassPhrase.An.Secure.Password".to_string(),
    );

    assert!(unsafe_password.is_err());
    assert!(safe_password.is_ok());
}
```

If the password is not encrypted, you can't access the inner value.
```rust 
fn main() {
    let mut password = Password::from_raw(
        "ThisIsAPassPhrase.An.Secure.Password".to_string(),
    );
    assert_eq!(password.try_to_str(), Err(Error::InexistentEncryptPassword));

    password.encrypt_password().unwrap();
    assert!(password.try_to_str().is_ok());
}
```
The `Password` type implements the `Debug` trait securely.
```rust
fn main(){
    let safe_password = Password::from_raw("ThisIsAPassPhrase.An.Secure.Password".to_string());
    let str_password = format!("{:?}", &safe_password);
    assert!(!str_password.contains("ThisIs"))
}
```
