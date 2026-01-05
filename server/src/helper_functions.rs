use crate::data_structures::Claims;
use crate::data_structures::EduLevel;
use crate::data_structures::User;
use axum::http::StatusCode;
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use surrealdb::Surreal;
use surrealdb::engine::local::Db;

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

pub async fn get_skills_eduinfo_from_uid(
    uid: String,
    db: &Surreal<Db>,
) -> Result<(Option<Vec<String>>, Option<Vec<(EduLevel, String)>>), StatusCode> {
    let (table, key) = uid.split_once(':').unwrap_or(("User", uid.as_str()));
    let user: User = db
        .select((table, key))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    if user.education.is_none() {
        return Ok((user.skills, None));
    }
    let mut edu_info: Vec<(EduLevel, String)> = Vec::new();
    let _ = user
        .education
        .unwrap()
        .into_iter()
        .map(|e| edu_info.push((e.education, e.major)));
    Ok((user.skills, Some(edu_info)))
}
