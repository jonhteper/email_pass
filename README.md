# email_pass
Email and Password Type in Rust

Include:

## Safe Email Constructor

```rust
    let correct_email = Email::new("example@example.com");
    let incorrect_email = Email::new("example.com");
    assert!(correct_email.is_ok());
    assert!(incorrect_email.is_err());
 ```

## Safe Passwords Constructor

```rust 
    let unsafe_password = Password::new(NonEmptyString::try_from("01234").unwrap());
    let safe_password = Password::new(
        NonEmptyString::try_from("ThisIsAPassPhrase.An.A.Secure.Password").unwrap(),
    );

    assert!(unsafe_password.is_err());
    assert!(safe_password.is_ok();
```

After initialization, you can't access the non encrypt value
```rust 
    let mut password = Password::from_raw(NonEmptyString::try_from("01234").unwrap());
    assert!(password.maybe_string.is_none());
    
    password.encrypt_password().unwrap();
    assert!(password.maybe_string.is_some());
```

