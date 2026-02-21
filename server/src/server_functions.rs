use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use axum::extract::Path;
use axum::{
    Extension, Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use chrono::NaiveDateTime;
use jsonwebtoken::{DecodingKey, Validation, decode};
use surrealdb::engine::local::Db;
use surrealdb::{RecordId, Surreal};

use crate::data_structures::*;
use crate::helper_functions::*;

pub async fn get_profile(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<UserProfile>, StatusCode> {
    let users: Vec<User> = db
        .query("SELECT * FROM User WHERE uid = $uid")
        .bind(("uid", claims.uid))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let user = users.first().ok_or(StatusCode::NOT_FOUND)?.clone();
    Ok(Json(UserProfile::from(user)))
}

pub async fn signup(
    State(db): State<Surreal<Db>>,
    Json(data): Json<SignupData>,
) -> Result<Json<String>, StatusCode> {
    let password_hash = hash_pword(&data.pword).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let user = User {
        id: None,
        uid: data.uid,
        pword_hash: password_hash,
        email: data.email,
        name: data.name,
        is_finding_job: true,
        education: None,
        current_work: None,
        previous_experience: None,
        skills: None,
    };
    let _: Option<User> = db
        .create("User")
        .content(user)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json("User created".to_string()))
}

pub async fn signin(
    State(db): State<Surreal<Db>>,
    Json(data): Json<SigninData>,
) -> Result<Json<TokenResponse>, StatusCode> {
    let user_details_vec: Vec<User> = db
        .query("SELECT * FROM User where uid=$uid")
        .bind(("uid", data.uid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let user_details: &User = user_details_vec.first().ok_or(StatusCode::UNAUTHORIZED)?;
    match verify_password(&data.pword, &user_details.pword_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        true => {
            let jwt_token = encode_jwt(data.uid)?;
            Ok(Json(TokenResponse { token: jwt_token }))
        }
        false => Err(StatusCode::UNAUTHORIZED),
    }
}

pub async fn home(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<DashboardResponse>, StatusCode> {
    let user = get_user_from_uid(claims.uid, &db).await?;
    if user.is_finding_job {
        let (skills_vec, edu_info_vec) = get_edu_skill_info(&user).await?;
        let jobs: Vec<JobsData> = get_jobs_data(skills_vec, edu_info_vec, &db).await?;
        Ok(Json(DashboardResponse::Jobs(jobs)))
    } else {
        let sql = "SELECT * FROM User WHERE is_finding_job = true";
        let mut response = db
            .query(sql)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let candidates: Vec<User> = response
            .take(0)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let candidates_data = candidates.into_iter().map(UserProfile::from).collect();
        Ok(Json(DashboardResponse::Candidates(candidates_data)))
    }
}

pub async fn get_user_info(
    State(db): State<Surreal<Db>>,
    Path(uid): Path<String>,
) -> Result<Json<UserProfile>, StatusCode> {
    let uid: RecordId = RecordId::from_str(&uid).map_err(|_| StatusCode::BAD_REQUEST)?;
    let user: Option<User> = db
        .select(uid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match user {
        Some(profile) => Ok(Json(UserProfile::from(profile))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_jobs_data(
    skills_vec: Option<Vec<String>>,
    edu_info_vec: Option<Vec<(u8, String)>>,
    db: &Surreal<Db>,
) -> Result<Vec<JobsData>, StatusCode> {
    let mut unique_jobs: HashMap<String, (Job, f32)> = HashMap::new(); // (Job, score)

    match (skills_vec, edu_info_vec) {
        (None, None) => {
            let jobs: Vec<Job> = db
                .query("SELECT * FROM jobs WHERE is_active = true ORDER BY rand() LIMIT 20")
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .take(0)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            for job in jobs {
                if let Some(id) = &job.id {
                    unique_jobs.insert(id.to_string(), (job, 0.5)); // Base score for random
                }
            }
        }

        (Some(skills), None) => {
            // Get jobs matching any skills
            let matched_jobs: Vec<Job> = db
                .query(
                    "SELECT * FROM jobs
                     WHERE is_active = true
                     AND skills_required CONTAINSANY $skills
                     ORDER BY rand() LIMIT 30",
                )
                .bind(("skills", skills.clone()))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .take(0)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            // Score based on number of matching skills
            for job in matched_jobs {
                if let Some(id) = &job.id {
                    let score = calculate_skill_match_score(&skills, &job.skills_required);
                    unique_jobs.insert(id.to_string(), (job, score));
                }
            }

            // If we have fewer than 15 jobs, add some random ones
            if unique_jobs.len() < 15 {
                let random_jobs: Vec<Job> = db
                    .query("SELECT * FROM jobs WHERE is_active = true ORDER BY rand() LIMIT 10")
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .take(0)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                for job in random_jobs {
                    if let Some(id) = &job.id {
                        unique_jobs.entry(id.to_string()).or_insert((job, 0.3));
                    }
                }
            }
        }

        // Case 3: Only education - filter by education level and majors
        (None, Some(edu_info)) => {
            // Extract all unique majors and find highest education level
            let majors: Vec<String> = edu_info.iter().map(|(_, major)| major.clone()).collect();
            let highest_edu_level = edu_info
                .iter()
                .map(|(level, _)| level.to_owned())
                .max()
                .unwrap_or(0);

            // Single query for all majors
            let matched_jobs: Vec<Job> = db
                .query(
                    "SELECT * FROM jobs
                     WHERE is_active = true
                     AND min_ed_lvl <= $edu_level
                     AND majors_accepted CONTAINSANY $majors
                     ORDER BY rand() LIMIT 30",
                )
                .bind(("edu_level", highest_edu_level))
                .bind(("majors", majors.clone()))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .take(0)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            for job in matched_jobs {
                if let Some(id) = &job.id {
                    let score = calculate_education_match_score(&majors, &job.majors_accepted);
                    unique_jobs.insert(id.to_string(), (job, score));
                }
            }

            // Fallback: Add jobs that match education level but not major
            if unique_jobs.len() < 15 {
                let fallback_jobs: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                         WHERE is_active = true
                         AND min_ed_lvl <= $edu_level
                         ORDER BY rand() LIMIT 15",
                    )
                    .bind(("edu_level", highest_edu_level))
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .take(0)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                for job in fallback_jobs {
                    if let Some(id) = &job.id {
                        unique_jobs.entry(id.to_string()).or_insert((job, 0.4));
                    }
                }
            }
        }

        // Case 4: Both skills and education - comprehensive matching with scoring
        (Some(skills), Some(edu_info)) => {
            let majors: Vec<String> = edu_info.iter().map(|(_, major)| major.clone()).collect();
            let highest_edu_level = edu_info
                .iter()
                .map(|(level, _)| level.to_owned())
                .max()
                .unwrap_or(0);

            // Get jobs matching both skills and education
            let perfect_matches: Vec<Job> = db
                .query(
                    "SELECT * FROM jobs
                     WHERE is_active = true
                     AND skills_required CONTAINSANY $skills
                     AND min_ed_lvl <= $edu_level
                     AND majors_accepted CONTAINSANY $majors
                     ORDER BY rand() LIMIT 30",
                )
                .bind(("skills", skills.clone()))
                .bind(("edu_level", highest_edu_level))
                .bind(("majors", majors.clone()))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .take(0)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            for job in perfect_matches {
                if let Some(id) = &job.id {
                    let skill_score = calculate_skill_match_score(&skills, &job.skills_required);
                    let edu_score = calculate_education_match_score(&majors, &job.majors_accepted);
                    let combined_score = (skill_score * 0.6) + (edu_score * 0.4); // Weight skills more
                    unique_jobs.insert(id.to_string(), (job, combined_score));
                }
            }

            // Fallback 1: Jobs matching skills only
            if unique_jobs.len() < 15 {
                let skill_matches: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                         WHERE is_active = true
                         AND skills_required CONTAINSANY $skills
                         AND min_ed_lvl <= $edu_level
                         ORDER BY rand() LIMIT 20",
                    )
                    .bind(("skills", skills.clone()))
                    .bind(("edu_level", highest_edu_level))
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .take(0)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                for job in skill_matches {
                    if let Some(id) = &job.id {
                        let score =
                            calculate_skill_match_score(&skills, &job.skills_required) * 0.7;
                        unique_jobs.entry(id.to_string()).or_insert((job, score));
                    }
                }
            }

            // Fallback 2: Jobs matching education only
            if unique_jobs.len() < 15 {
                let edu_matches: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                         WHERE is_active = true
                         AND min_ed_lvl <= $edu_level
                         AND majors_accepted CONTAINSANY $majors
                         ORDER BY rand() LIMIT 15",
                    )
                    .bind(("edu_level", highest_edu_level))
                    .bind(("majors", majors.clone()))
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .take(0)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                for job in edu_matches {
                    if let Some(id) = &job.id {
                        let score =
                            calculate_education_match_score(&majors, &job.majors_accepted) * 0.6;
                        unique_jobs.entry(id.to_string()).or_insert((job, score));
                    }
                }
            }

            // Final fallback: Random jobs matching education level
            if unique_jobs.len() < 10 {
                let random_jobs: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                         WHERE is_active = true
                         AND min_ed_lvl <= $edu_level
                         ORDER BY rand() LIMIT 10",
                    )
                    .bind(("edu_level", highest_edu_level))
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .take(0)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                for job in random_jobs {
                    if let Some(id) = &job.id {
                        unique_jobs.entry(id.to_string()).or_insert((job, 0.3));
                    }
                }
            }
        }
    };

    // Sort by score (highest first) and take top 20
    let mut sorted_jobs: Vec<(Job, f32)> = unique_jobs.into_values().collect();
    sorted_jobs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    sorted_jobs.truncate(20);

    // Fetch employer names concurrently
    let database = db.clone();
    let futures = sorted_jobs.into_iter().map(|(job, _score)| {
        let db = database.clone();
        async move {
            let employer_id_str = job.employer_id.to_string();
            let (table, key) = employer_id_str
                .split_once(':')
                .map(|(t, k)| (t.to_string(), k.to_string()))
                .unwrap_or_else(|| ("User".to_string(), employer_id_str.clone()));

            let mut result = db
                .query("SELECT VALUE name FROM type::thing($table, $key)")
                .bind(("table", table))
                .bind(("key", key))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let name: Option<String> = result
                .take(0)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            Ok::<JobsData, StatusCode>(JobsData {
                id: job.id.unwrap().to_string(),
                employer_name: name.unwrap_or_default(),
                employer_id: job.employer_id.to_string(),
                title: job.title,
                description: job.description,
                skills_required: job.skills_required,
                majors_accepted: job.majors_accepted,
                location: job.location,
                is_active: job.is_active,
                salary_range_start: job.salary_range_start,
                salary_range_end: job.salary_range_end,
                datetime_created: job.datetime_created,
                datetime_due: job.datetime_due,
                min_ed_lvl: EduLevel::try_from(job.min_ed_lvl).unwrap(),
            })
        }
    });

    let results = futures::future::join_all(futures).await;
    let jobs_data: Vec<JobsData> = results.into_iter().filter_map(|r| r.ok()).collect();

    Ok(jobs_data)
}

fn calculate_skill_match_score(user_skills: &[String], job_skills: &[String]) -> f32 {
    if job_skills.is_empty() {
        return 0.5; // Neutral score if job has no skill requirements
    }

    let user_skills_set: HashSet<&String> = user_skills.iter().collect();
    let job_skills_set: HashSet<&String> = job_skills.iter().collect();

    let matching_skills = user_skills_set.intersection(&job_skills_set).count();
    let total_job_skills = job_skills.len();

    let match_percentage = matching_skills as f32 / total_job_skills as f32;

    let extra_skills_bonus = if matching_skills > 0 { 0.1 } else { 0.0 };

    (match_percentage + extra_skills_bonus).min(1.0)
}

fn calculate_education_match_score(user_majors: &[String], job_majors: &[String]) -> f32 {
    if job_majors.is_empty() {
        return 0.6;
    }

    let user_majors_set: HashSet<&String> = user_majors.iter().collect();
    let job_majors_set: HashSet<&String> = job_majors.iter().collect();

    let matching_majors = user_majors_set.intersection(&job_majors_set).count();

    if matching_majors > 0 { 0.9 } else { 0.4 }
}

pub async fn auth_middleware(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|auth| auth.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret("ThisIsTheSecretKeyForTheApp".as_ref()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    req.extensions_mut().insert(claims.claims);
    Ok(next.run(req).await)
}

pub async fn create_job(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
    Json(data): Json<CreateJobRequest>,
) -> Result<Json<String>, StatusCode> {
    let users: Vec<User> = db
        .query("SELECT * FROM User WHERE uid = $uid")
        .bind(("uid", claims.uid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = users.first().ok_or(StatusCode::NOT_FOUND)?;
    let employer_id = user.id.clone().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let datetime_due: Option<NaiveDateTime> =
        NaiveDateTime::from_str(data.datetime_due.as_str()).ok();
    let job: Job = Job {
        id: None,
        employer_id,
        title: data.title,
        description: data.description,
        skills_required: data.skills_required.unwrap_or_default(),
        majors_accepted: data.majors_accepted.unwrap_or_default(),
        location: data.location,
        is_active: true,
        salary_range_start: data.salary_range_start.unwrap_or_default(),
        salary_range_end: data.salary_range_end.unwrap_or_default(),
        datetime_created: chrono::DateTime::parse_from_rfc3339(
            chrono::Utc::now().to_rfc3339().as_str(),
        )
        .map(|dt| dt.naive_utc())
        .unwrap_or_default(),
        datetime_due,
        min_ed_lvl: data.min_ed_lvl as u8,
    };

    let created: Option<Job> = db
        .create("jobs")
        .content(job)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match created {
        Some(job) => Ok(Json(format!("Job post created with ID: {:?}", job.id))),
        None => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn update_profile(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
    Json(data): Json<UpdateProfileRequest>,
) -> Result<Json<UserProfile>, StatusCode> {
    // First, get the current user
    let users: Vec<User> = db
        .query("SELECT * FROM User WHERE uid = $uid")
        .bind(("uid", claims.uid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let current_user = users.first().ok_or(StatusCode::NOT_FOUND)?;
    let user_id = current_user
        .id
        .clone()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut updates = Vec::new();

    if let Some(name) = &data.name {
        updates.push(format!("name = '{}'", name.replace("'", "''")));
    }
    if let Some(email) = &data.email {
        updates.push(format!("email = '{}'", email.replace("'", "''")));
    }
    if let Some(is_finding_job) = data.is_finding_job {
        updates.push(format!("is_finding_job = {}", is_finding_job));
    }
    if let Some(skills) = &data.skills {
        let skills_json =
            serde_json::to_string(skills).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        updates.push(format!("skills = {}", skills_json));
    }
    if let Some(education) = data.education {
        let edu_vec: Vec<Education> = education.into_iter().map(Education::from).collect();
        let edu_json =
            serde_json::to_string(&edu_vec).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        updates.push(format!("education = {}", edu_json));
    }
    if let Some(current_work) = &data.current_work {
        let work_json =
            serde_json::to_string(current_work).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        updates.push(format!("current_work = {}", work_json));
    }
    if let Some(previous_experience) = &data.previous_experience {
        let exp_json = serde_json::to_string(previous_experience)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        updates.push(format!("previous_experience = {}", exp_json));
    }

    if updates.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let update_query = format!("UPDATE {} SET {}", user_id, updates.join(", "));

    let _: Option<User> = db
        .query(&update_query)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let updated_users: Vec<User> = db
        .query("SELECT * FROM User WHERE uid = $uid")
        .bind(("uid", claims.uid))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let updated_user = updated_users.first().ok_or(StatusCode::NOT_FOUND)?.clone();

    Ok(Json(UserProfile::from(updated_user)))
}
