//! `BLOOM_RELAY_DATABASE_PASSWORD_FILE` supplies the password for a URL that
//! has none. Its own test binary, because it sets process environment.
//! Run with a disposable PostgreSQL URL in `BLOOM_RELAY_TEST_DATABASE_URL`
//! that includes a password.

use bloom_relay_store::Store;

#[tokio::test]
async fn the_password_comes_from_the_named_file() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let mut parsed = url::Url::parse(&url).unwrap();
    let password = parsed
        .password()
        .expect("test URL has a password")
        .to_owned();
    parsed.set_password(None).unwrap();
    let without_password = parsed.to_string();
    let file = std::env::temp_dir().join(format!("bloom-relay-password-{}", uuid::Uuid::new_v4()));

    // SAFETY: this binary's only test is the sole reader of the variable.
    unsafe { std::env::set_var("BLOOM_RELAY_DATABASE_PASSWORD_FILE", &file) };
    std::fs::write(&file, format!("{password}\n")).unwrap();
    Store::connect(&without_password).await.unwrap();

    std::fs::write(&file, "wrong-password\n").unwrap();
    assert!(Store::connect(&without_password).await.is_err());

    std::fs::write(&file, "").unwrap();
    assert!(Store::connect(&without_password).await.is_err());

    std::fs::remove_file(&file).unwrap();
    assert!(Store::connect(&without_password).await.is_err());
    unsafe { std::env::remove_var("BLOOM_RELAY_DATABASE_PASSWORD_FILE") };
}
