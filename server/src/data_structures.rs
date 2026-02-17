use chrono::NaiveDateTime;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use surrealdb::RecordId;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum EduLevel {
    SecondarySchool = 0,
    HighSchool = 1,
    Diploma = 2,
    Bachelors = 3,
    Masters = 4,
    PhD = 5,
}
impl FromStr for EduLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SecondarySchool" => Ok(EduLevel::SecondarySchool),
            "HighSchool" => Ok(EduLevel::HighSchool),
            "Diploma" => Ok(EduLevel::Diploma),
            "Bachelors" => Ok(EduLevel::Bachelors),
            "Masters" => Ok(EduLevel::Masters),
            "PhD" => Ok(EduLevel::PhD),
            _ => Err(()),
        }
    }
}

impl TryFrom<u8> for EduLevel {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EduLevel::SecondarySchool),
            1 => Ok(EduLevel::HighSchool),
            2 => Ok(EduLevel::Diploma),
            3 => Ok(EduLevel::Bachelors),
            4 => Ok(EduLevel::Masters),
            5 => Ok(EduLevel::PhD),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for EduLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EduLevel::SecondarySchool => write!(f, "SecondarySchool"),
            EduLevel::HighSchool => write!(f, "HighSchool"),
            EduLevel::Diploma => write!(f, "Diploma"),
            EduLevel::Bachelors => write!(f, "Bachelors"),
            EduLevel::Masters => write!(f, "Masters"),
            EduLevel::PhD => write!(f, "PhD"),
        }
    }
}
fn deserialize_edu_level<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let level = EduLevel::from_str(&s)
        .map_err(|_| serde::de::Error::custom("Invalid Education Level Value"))?;
    Ok(level as u8)
}

fn serialize_edu_level<S>(value: &u8, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let level = EduLevel::try_from(*value)
        .map_err(|_| serde::ser::Error::custom("Invalid education level"))?;
    serializer.serialize_str(&level.to_string())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Education {
    #[serde(
        serialize_with = "serialize_edu_level",
        deserialize_with = "deserialize_edu_level"
    )]
    pub education: u8,
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

#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub id: String,
    pub uid: String,
    pub name: String,
    pub is_finding_job: bool,
    pub email: String,
    pub education: Option<Vec<Education>>,
    pub skills: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(tag = "mode", content = "payload")]
pub enum DashboardResponse {
    #[serde(rename = "jobs")]
    Jobs(Vec<JobsData>),
    #[serde(rename = "candidates")]
    Candidates(Vec<UserProfile>),
}

#[derive(Deserialize)]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
    pub email: Option<String>,
    pub is_finding_job: Option<bool>,
    pub skills: Option<Vec<String>>,
    pub education: Option<Vec<EducationUpdateRequest>>,
    pub current_work: Option<Work>,
    pub previous_experience: Option<Vec<Work>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EducationUpdateRequest {
    pub education: EduLevel,
    pub major: String,
    pub edu_institution: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Claims {
    pub uid: String,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub datetime_due: Option<NaiveDateTime>,
    pub min_ed_lvl: EduLevel,
}

#[derive(Serialize, Deserialize)]
pub struct CreateJobRequest {
    pub title: String,
    pub description: String,
    pub skills_required: Option<Vec<String>>,
    pub majors_accepted: Option<Vec<String>>,
    pub location: String,
    pub salary_range_start: Option<u32>,
    pub salary_range_end: Option<u32>,
    pub datetime_due: String,
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
    pub datetime_due: Option<NaiveDateTime>,
    pub min_ed_lvl: u8,
}

impl From<EducationUpdateRequest> for Education {
    fn from(value: EducationUpdateRequest) -> Self {
        Education {
            education: value.education as u8,
            major: value.major,
            edu_institution: value.edu_institution,
        }
    }
}
