use crate::data_structures::Claims;
use axum::http::StatusCode;
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};

pub fn hash_pword(pword: &str) -> Result<String, bcrypt::BcryptError> {
    hash(pword, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

pub fn encode_jwt(uid: String) -> Result<String, StatusCode> {
    let secret = "ThisIsTheSecretKeyForTheApp";
    let now = Utc::now();
    let expire = Duration::hours(24);
    let claims = Claims {
        uid,
        exp: (now + expire).timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    let encoding_key: EncodingKey = EncodingKey::from_secret(secret.as_ref());
    encode(&Header::default(), &claims, &encoding_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
