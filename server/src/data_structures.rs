use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum EduLevel {
    SecondarySchool = 0,
    HighSchool = 1,
    Diploma = 2,
    Bachelors = 3,
    Masters = 4,
    PhD = 5,
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
    // TODO: add PFP support
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

#[allow(unused)]
#[derive(Serialize, Deserialize)]
pub struct JobFilters {
    min_sal: Option<u32>,
    max_sal: Option<u32>,
    location: Option<Vec<String>>,
    skills: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JobsData {
    pub id: String,
    pub employer_name: String,
    pub title: String,
    // pub company_id: RecordId, // Left for later implementation
    // TODO: Add support for images for posts
    pub description: String,
    pub skills_required: Vec<String>,
    pub majors_accepted: Vec<String>,
    pub location: String,
    pub is_active: bool,
    pub salary_range_start: u32,
    pub salary_range_end: u32,
    pub datetime_created: NaiveDateTime,
    pub datetime_due: NaiveDateTime,
    pub min_ed_lvl: EduLevel,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: Option<RecordId>,
    pub employer_id: RecordId,
    // pub company_id: RecordId, // Left for later implementation
    // TODO: Add support for images for posts
    pub title: String,
    pub description: String,
    pub skills_required: Vec<String>,
    pub majors_accepted: Vec<String>,
    pub location: String,
    pub is_active: bool,
    pub salary_range_start: u32,
    pub salary_range_end: u32,
    pub datetime_created: NaiveDateTime,
    pub datetime_due: NaiveDateTime,
    pub min_ed_lvl: EduLevel,
}
