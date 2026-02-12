use crate::data_structures::Claims;
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
) -> Result<(Option<Vec<String>>, Option<Vec<(u8, String)>>), StatusCode> {
    let users: Vec<User> = db
        .query("SELECT * FROM User WHERE uid = $uid")
        .bind(("uid", uid))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = users.first().ok_or(StatusCode::NOT_FOUND)?;

    if user.education.as_deref().is_none_or(|e| e.is_empty())
        && user.skills.as_deref().is_none_or(|e| e.is_empty())
    {
        Ok((None, None))
    } else if user.education.as_deref().is_none_or(|e| e.is_empty())
        && user.skills.as_deref().is_none_or(|e| !e.is_empty())
    {
        Ok((user.skills.clone(), None))
    } else if user.education.as_deref().is_none_or(|e| !e.is_empty())
        && user.skills.as_deref().is_none_or(|e| e.is_empty())
    {
        let mut edu_info: Vec<(u8, String)> = Vec::new();
        for e in user.education.as_ref().unwrap() {
            edu_info.push((e.education, e.major.clone()));
        }
        Ok((None, Some(edu_info)))
    } else {
        let mut edu_info: Vec<(u8, String)> = Vec::new();
        for e in user.education.as_ref().unwrap() {
            edu_info.push((e.education, e.major.clone()));
        }

        Ok((user.skills.clone(), Some(edu_info)))
    }
}
