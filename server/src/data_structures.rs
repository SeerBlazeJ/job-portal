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
    pub is_finding_job: bool,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: String,
    pub uid: String,
    pub name: String,
    pub is_finding_job: bool,
    pub email: String,
    pub education: Option<Vec<Education>>,
    pub skills: Option<Vec<String>>,
    pub current_work: Option<Work>,
    pub previous_experience: Option<Vec<Work>>,
    pub profile_picture: Option<String>,
    pub resume: Option<String>,
    pub about_user: Option<String>,
    pub working_at: Option<Vec<UserCompanyData>>,
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
    pub profile_picture: Option<String>,
    pub resume: Option<String>,
    pub about_user: Option<String>,
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
    pub uid: String,
    pub pword_hash: String,
    pub name: String,
    pub is_finding_job: bool,
    pub email: String,
    pub education: Option<Vec<Education>>,
    pub skills: Option<Vec<String>>,
    pub current_work: Option<Work>,
    pub previous_experience: Option<Vec<Work>>,
    pub profile_picture: Option<String>,
    pub resume: Option<String>,
    pub about_user: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Work {
    pub worked_as: String,
    pub company: String,
    pub exp: u16,
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
    pub employer_id: String,
    pub title: String,
    #[serde(default)]
    pub company_name: String,
    #[serde(default)]
    pub company_id: Option<String>,
    #[serde(default)]
    pub min_experience: Option<u16>,
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
    pub has_applied: Option<bool>,
    pub photos: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateJobRequest {
    pub title: String,
    pub company_name: String,
    pub company_id: String,
    pub min_experience: Option<u16>,
    pub description: String,
    pub skills_required: Option<Vec<String>>,
    pub majors_accepted: Option<Vec<String>>,
    pub location: String,
    pub salary_range_start: Option<u32>,
    pub salary_range_end: Option<u32>,
    pub datetime_due: String,
    pub min_ed_lvl: EduLevel,
    pub photos: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: Option<RecordId>,
    pub employer_id: RecordId,
    pub title: String,
    #[serde(default)]
    pub company_name: String,
    #[serde(default)]
    pub company_id: Option<RecordId>,
    #[serde(default)]
    pub min_experience: Option<u16>,
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
    pub photos: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Application {
    pub id: Option<RecordId>,
    #[serde(rename = "in")]
    pub applicant: RecordId,
    pub out: RecordId,
    pub employer_id: Option<RecordId>,
    pub datetime_applied: Option<String>,
    pub status: String,
}

#[derive(Serialize)]
pub struct ApplicantData {
    pub user: UserProfile,
    pub datetime_applied: String,
    pub status: String,
}

#[derive(Deserialize, Debug)]
pub struct ApplicationRequest {
    pub job_id: String,
    pub employer_id: String,
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

impl From<User> for UserProfile {
    fn from(c: User) -> Self {
        Self {
            id: c.id.map(|c| c.to_string()).unwrap(),
            education: c.education,
            email: c.email,
            is_finding_job: c.is_finding_job,
            name: c.name,
            skills: c.skills,
            uid: c.uid,
            previous_experience: c.previous_experience,
            current_work: c.current_work,
            profile_picture: c.profile_picture,
            resume: c.resume,
            about_user: c.about_user,
            working_at: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Company {
    pub id: Option<RecordId>,
    pub created_by: RecordId,
    pub name: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub logo: Option<String>,
    pub website: Option<String>,
}

#[derive(Serialize)]
pub struct CompanyData {
    pub id: String,
    pub created_by: String,
    pub name: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub logo: Option<String>,
    pub website: Option<String>,
}

impl From<Company> for CompanyData {
    fn from(c: Company) -> Self {
        Self {
            id: c.id.unwrap().to_string(),
            created_by: c.created_by.to_string(),
            name: c.name,
            description: c.description,
            location: c.location,
            logo: c.logo,
            website: c.website,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub struct works_for {
    pub id: Option<RecordId>,
    #[serde(rename = "in")]
    pub user: RecordId,
    pub out: RecordId,
    pub designation: String,
    pub employee_since: i64,
    pub is_verified: bool,
}

#[derive(Deserialize)]
pub struct CreateCompanyRequest {
    pub name: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub designation: String,
}

#[derive(Deserialize)]
pub struct JoinCompanyRequest {
    pub company_id: String,
    pub designation: String,
}

#[derive(Serialize)]
pub struct EmployeeData {
    pub user: UserProfile,
    pub designation: String,
    pub employee_since: i64,
    pub is_verified: bool,
}

#[derive(Serialize)]
pub struct CompanyProfileResponse {
    pub company: CompanyData,
    pub employees: Vec<EmployeeData>,
    pub is_employee: bool,
    pub is_owner: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserCompanyData {
    pub company_id: String,
    pub company_name: String,
    pub designation: String,
    pub is_verified: bool,
    pub is_owner: bool,
}

#[derive(Deserialize)]
pub struct WorksForQueryResult {
    pub company_id: RecordId,
    pub company_name: String,
    pub creator_id: RecordId,
    pub designation: String,
    pub is_verified: bool,
}

// Replace these at the bottom of src/data_structures.rs

#[derive(Serialize, Deserialize)]
pub struct UpdateCompanyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateJobRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company_id: Option<String>, // <--- Change this back to Option<String>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_experience: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills_required: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub majors_accepted: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salary_range_start: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salary_range_end: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datetime_due: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ed_lvl: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub photos: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct MergeJobData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company_id: Option<RecordId>, // Native RecordId for DB merging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_experience: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills_required: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub majors_accepted: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salary_range_start: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salary_range_end: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datetime_due: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ed_lvl: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub photos: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct VerifyEmployeeRequest {
    pub company_id: String,
    pub user_id: String,
}

#[derive(Deserialize)]
pub struct UpdateApplicationStatusRequest {
    pub job_id: String,
    pub applicant_id: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct MyApplicationData {
    pub job: JobsData,
    pub status: String,
    pub datetime_applied: String,
}
#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

impl From<UpdateJobRequest> for MergeJobData {
    fn from(req: UpdateJobRequest) -> Self {
        let company_id = req
            .company_id
            .and_then(|id_str| RecordId::from_str(&id_str).ok());
        Self {
            title: req.title,
            company_name: req.company_name,
            company_id,
            min_experience: req.min_experience,
            description: req.description,
            skills_required: req.skills_required,
            majors_accepted: req.majors_accepted,
            location: req.location,
            salary_range_start: req.salary_range_start,
            salary_range_end: req.salary_range_end,
            datetime_due: req.datetime_due,
            min_ed_lvl: req.min_ed_lvl,
            photos: req.photos,
        }
    }
}

#[derive(Deserialize)]
pub struct GlobalSearchQuery {
    pub q: Option<String>,
    pub category: Option<String>, // "all", "users", "jobs", "companies"
    pub is_finding_job: Option<bool>,
    pub location: Option<String>,
}

#[derive(Serialize)]
pub struct GlobalSearchResponse {
    pub users: Vec<UserProfile>,
    pub jobs: Vec<JobsData>,
    pub companies: Vec<CompanyData>,
}
