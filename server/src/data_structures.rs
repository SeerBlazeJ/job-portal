use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Clone, Serialize, Deserialize)]
pub enum EduLevel {
    SecondarySchool,
    HighSchool,
    Diploma,
    Bachelors,
    Masters,
    PhD,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Education {
    pub education: EduLevel,
    pub major: String,
    pub edu_institution: String,
}

#[derive(Deserialize)]
pub struct SignupData {
    pub name: String,
    pub email: String,
    pub uid: String,
    pub pword: String,
}
#[derive(Deserialize)]
pub struct SigninData {
    pub uid: String,
    pub pword: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
}

#[derive(Serialize)]
pub struct UserProfile {
    pub id: String,
    pub uid: String,
    pub name: String,
    pub is_finding_job: bool,
    pub email: String,
    pub education: Option<Vec<Education>>,
    pub skills: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Claims {
    pub uid: String,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Option<RecordId>,
    pub uid: String,
    pub pword_hash: String,
    pub name: String,
    pub is_finding_job: bool,
    pub email: String,
    pub education: Option<Vec<Education>>,
    pub skills: Option<Vec<String>>,
    pub current_work: Option<Work>,
    pub previous_experience: Option<Vec<Work>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Work {
    pub worked_as: String,
    pub company: String,
    pub exp: chrono::Duration,
}
