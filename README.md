# email_pass
Email and Password Type in Rust

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
        "ThisIsAPassPhrase.And.Secure.Password".to_string(),
    );

    assert!(unsafe_password.is_err());
    assert!(safe_password.is_ok());
}
```

If the password is not encrypted, you can't access the inner value.
```rust 
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

### Compile Time Safe Password
The type `passwords::Password` differentiates the raw password from encrypted passwords 
and provides only the correct methods for each. 
```rust
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
fn main() {
    let password = password::Password::new("ThisIsAPassPhrase.And.Secure.Password");
    println!("{}", &password); // ❌
    println!("{:?}", &password); // ❌ 
}
```

### Acknowledgments
Thanks to [letsgetrusty](https://github.com/letsgetrusty/) for the 
[repo that inspired](https://github.com/letsgetrusty/generics_and_zero_sized_types) the `password::Password` type.