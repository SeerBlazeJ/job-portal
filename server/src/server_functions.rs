use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use axum::extract::{Path, Query};
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

    let mut profile = UserProfile::from(user.clone());
    if let Some(user_id) = &user.id {
        profile.working_at = get_working_at(&db, user_id).await;
    }

    Ok(Json(profile))
}

pub async fn signup(
    State(db): State<Surreal<Db>>,
    Json(data): Json<SignupData>,
) -> Result<Json<String>, StatusCode> {
    let existing_users: Vec<User> = db
        .query("SELECT * FROM User WHERE uid = $uid")
        .bind(("uid", data.uid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !existing_users.is_empty() {
        return Err(StatusCode::CONFLICT); // 409 Conflict
    }
    let password_hash = hash_pword(&data.pword).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let user = User {
        id: None,
        uid: data.uid,
        pword_hash: password_hash,
        email: data.email,
        name: data.name,
        is_finding_job: data.is_finding_job,
        education: None,
        current_work: None,
        previous_experience: None,
        skills: None,
        resume: None,
        profile_picture: None,
        about_user: None,
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

        // Calculate total experience in months
        let mut total_exp_months: u16 = 0;
        if let Some(cw) = &user.current_work {
            total_exp_months += cw.exp;
        }
        if let Some(pe) = &user.previous_experience {
            for work in pe {
                total_exp_months += work.exp;
            }
        }

        // Pass total_exp_months to get_jobs_data
        let mut jobs: Vec<JobsData> =
            get_jobs_data(skills_vec, edu_info_vec, total_exp_months, &db).await?;

        if let Some(user_id) = &user.id {
            let mut response = db
                .query("SELECT * FROM application WHERE in = $uid")
                .bind(("uid", user_id.clone()))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let applied: Vec<Application> = response.take(0).unwrap_or_default();
            let applied_ids: HashSet<String> =
                applied.into_iter().map(|a| a.out.to_string()).collect();

            // Filters jobs user already applied for
            jobs.retain(|job| !applied_ids.contains(&job.id));
        }

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

        let mut candidates_data = Vec::new();
        for u in candidates {
            let mut profile = UserProfile::from(u.clone());
            if let Some(user_id) = &u.id {
                profile.working_at = get_working_at(&db, user_id).await;
            }
            candidates_data.push(profile);
        }
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
        Some(u) => {
            let mut profile = UserProfile::from(u.clone());
            if let Some(user_id) = &u.id {
                profile.working_at = get_working_at(&db, user_id).await;
            }
            Ok(Json(profile))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_jobs_data(
    skills_vec: Option<Vec<String>>,
    edu_info_vec: Option<Vec<(u8, String)>>,
    total_exp_months: u16, // <-- ADDED
    db: &Surreal<Db>,
) -> Result<Vec<JobsData>, StatusCode> {
    let mut unique_jobs: HashMap<String, (Job, f32)> = HashMap::new();

    // Reusable filter string for readability (though we'll embed it in multi-line strings below)
    // AND (min_experience <= $exp OR min_experience = NONE)

    match (skills_vec, edu_info_vec) {
        (None, None) => {
            let jobs: Vec<Job> = db
                .query("SELECT * FROM jobs WHERE is_active = true AND (min_experience <= $exp OR min_experience = NONE) ORDER BY rand() LIMIT 20")
                .bind(("exp", total_exp_months)) // <-- BOUND HERE
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .take(0)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            for job in jobs {
                if let Some(id) = &job.id {
                    unique_jobs.insert(id.to_string(), (job, 0.5));
                }
            }
        }

        (Some(skills), None) => {
            let matched_jobs: Vec<Job> = db
                .query(
                    "SELECT * FROM jobs
                     WHERE is_active = true
                     AND skills_required CONTAINSANY $skills
                     AND (min_experience <= $exp OR min_experience = NONE)
                     ORDER BY rand() LIMIT 30",
                )
                .bind(("skills", skills.clone()))
                .bind(("exp", total_exp_months)) // <-- BOUND HERE
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .take(0)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            for job in matched_jobs {
                if let Some(id) = &job.id {
                    let score = calculate_skill_match_score(&skills, &job.skills_required);
                    unique_jobs.insert(id.to_string(), (job, score));
                }
            }

            if unique_jobs.len() < 15 {
                let random_jobs: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                         WHERE is_active = true
                         AND (min_experience <= $exp OR min_experience = NONE)
                         ORDER BY rand() LIMIT 10",
                    )
                    .bind(("exp", total_exp_months)) // <-- BOUND HERE
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

        (None, Some(edu_info)) => {
            let majors: Vec<String> = edu_info.iter().map(|(_, major)| major.clone()).collect();
            let highest_edu_level = edu_info
                .iter()
                .map(|(level, _)| level.to_owned())
                .max()
                .unwrap_or(0);

            let matched_jobs: Vec<Job> = db
                .query(
                    "SELECT * FROM jobs
                     WHERE is_active = true
                     AND min_ed_lvl <= $edu_level
                     AND majors_accepted CONTAINSANY $majors
                     AND (min_experience <= $exp OR min_experience = NONE)
                     ORDER BY rand() LIMIT 30",
                )
                .bind(("edu_level", highest_edu_level))
                .bind(("majors", majors.clone()))
                .bind(("exp", total_exp_months)) // <-- BOUND HERE
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

            if unique_jobs.len() < 15 {
                let fallback_jobs: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                         WHERE is_active = true
                         AND min_ed_lvl <= $edu_level
                         AND (min_experience <= $exp OR min_experience = NONE)
                         ORDER BY rand() LIMIT 15",
                    )
                    .bind(("edu_level", highest_edu_level))
                    .bind(("exp", total_exp_months)) // <-- BOUND HERE
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

        (Some(skills), Some(edu_info)) => {
            let majors: Vec<String> = edu_info.iter().map(|(_, major)| major.clone()).collect();
            let highest_edu_level = edu_info
                .iter()
                .map(|(level, _)| level.to_owned())
                .max()
                .unwrap_or(0);

            let perfect_matches: Vec<Job> = db
                .query(
                    "SELECT * FROM jobs
                     WHERE is_active = true
                     AND skills_required CONTAINSANY $skills
                     AND min_ed_lvl <= $edu_level
                     AND majors_accepted CONTAINSANY $majors
                     AND (min_experience <= $exp OR min_experience = NONE)
                     ORDER BY rand() LIMIT 30",
                )
                .bind(("skills", skills.clone()))
                .bind(("edu_level", highest_edu_level))
                .bind(("majors", majors.clone()))
                .bind(("exp", total_exp_months)) // <-- BOUND HERE
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .take(0)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            for job in perfect_matches {
                if let Some(id) = &job.id {
                    let skill_score = calculate_skill_match_score(&skills, &job.skills_required);
                    let edu_score = calculate_education_match_score(&majors, &job.majors_accepted);
                    let combined_score = (skill_score * 0.6) + (edu_score * 0.4);
                    unique_jobs.insert(id.to_string(), (job, combined_score));
                }
            }

            if unique_jobs.len() < 15 {
                let skill_matches: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                         WHERE is_active = true
                         AND skills_required CONTAINSANY $skills
                         AND min_ed_lvl <= $edu_level
                         AND (min_experience <= $exp OR min_experience = NONE)
                         ORDER BY rand() LIMIT 20",
                    )
                    .bind(("skills", skills.clone()))
                    .bind(("edu_level", highest_edu_level))
                    .bind(("exp", total_exp_months)) // <-- BOUND HERE
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

            if unique_jobs.len() < 15 {
                let edu_matches: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                         WHERE is_active = true
                         AND min_ed_lvl <= $edu_level
                         AND majors_accepted CONTAINSANY $majors
                         AND (min_experience <= $exp OR min_experience = NONE)
                         ORDER BY rand() LIMIT 15",
                    )
                    .bind(("edu_level", highest_edu_level))
                    .bind(("majors", majors.clone()))
                    .bind(("exp", total_exp_months)) // <-- BOUND HERE
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

            if unique_jobs.len() < 10 {
                let random_jobs: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                         WHERE is_active = true
                         AND min_ed_lvl <= $edu_level
                         AND (min_experience <= $exp OR min_experience = NONE)
                         ORDER BY rand() LIMIT 10",
                    )
                    .bind(("edu_level", highest_edu_level))
                    .bind(("exp", total_exp_months)) // <-- BOUND HERE
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

    let mut sorted_jobs: Vec<(Job, f32)> = unique_jobs.into_values().collect();
    sorted_jobs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    sorted_jobs.truncate(20);

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
                company_name: job.company_name,
                company_id: job.company_id.clone().map(|id| id.to_string()),
                min_experience: job.min_experience,
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
                has_applied: None,
                photos: job.photos,
            })
        }
    });

    let results = futures::future::join_all(futures).await;
    let jobs_data: Vec<JobsData> = results.into_iter().filter_map(|r| r.ok()).collect();

    Ok(jobs_data)
}

fn calculate_skill_match_score(user_skills: &[String], job_skills: &[String]) -> f32 {
    if job_skills.is_empty() {
        return 0.5;
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
    let company_id = RecordId::from_str(&data.company_id).ok();
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
        company_id,
        company_name: data.company_name,
        min_experience: data.min_experience,
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
        photos: data.photos,
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
    if let Some(profile_picture) = &data.profile_picture {
        updates.push(format!(
            "profile_picture = '{}'",
            profile_picture.replace("'", "''")
        ));
    }
    if let Some(resume) = &data.resume {
        updates.push(format!("resume = '{}'", resume.replace("'", "''")));
    }
    if let Some(about_user) = &data.about_user {
        updates.push(format!("about_user = '{}'", about_user.replace("'", "''")));
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
    let mut profile = UserProfile::from(updated_user.clone());
    if let Some(user_id) = &updated_user.id {
        profile.working_at = get_working_at(&db, user_id).await;
    }

    Ok(Json(profile))
}

pub async fn apply_for_job(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
    Json(data): Json<ApplicationRequest>,
) -> Result<StatusCode, StatusCode> {
    let users: Vec<User> = db
        .query("SELECT * FROM User WHERE uid = $uid")
        .bind(("uid", claims.uid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = users.first().ok_or(StatusCode::NOT_FOUND)?;
    let user_record_id = user.id.clone().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let job_record_id = RecordId::from_str(&data.job_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let employer_record_id =
        RecordId::from_str(&data.employer_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let datetime_applied = chrono::Utc::now().to_rfc3339();
    let status = "Pending".to_string();

    let sql = "RELATE $applicant->application->$job SET datetime_applied = $datetime, employer_id = $employer, status = $status;";

    let response = db
        .query(sql)
        .bind(("applicant", user_record_id))
        .bind(("job", job_record_id))
        .bind(("datetime", datetime_applied))
        .bind(("employer", employer_record_id))
        .bind(("status", status))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    response
        .check()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::ACCEPTED)
}

pub async fn get_my_jobs(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<JobsData>>, StatusCode> {
    let users: Vec<User> = db
        .query("SELECT * FROM User WHERE uid = $uid")
        .bind(("uid", claims.uid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = users.first().ok_or(StatusCode::NOT_FOUND)?;
    let user_id = user.id.clone().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut result = db
        .query("SELECT * FROM jobs WHERE employer_id = $emp_id ORDER BY datetime_created DESC")
        .bind(("emp_id", user_id))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let jobs: Vec<Job> = result
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let employer_name = user.name.clone();
    let jobs_data: Vec<JobsData> = jobs
        .into_iter()
        .map(|job| JobsData {
            id: job.id.unwrap().to_string(),
            employer_name: employer_name.clone(),
            employer_id: job.employer_id.to_string(),
            title: job.title,
            company_name: job.company_name,
            company_id: job.company_id.clone().map(|id| id.to_string()),
            min_experience: job.min_experience,
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
            has_applied: None,
            photos: job.photos,
        })
        .collect();

    Ok(Json(jobs_data))
}

pub async fn get_job_applicants(
    State(db): State<Surreal<Db>>,
    Path(job_id): Path<String>,
    Extension(_claims): Extension<Claims>,
) -> Result<Json<Vec<ApplicantData>>, StatusCode> {
    let job_record_id = RecordId::from_str(&job_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut result = db
        .query("SELECT * FROM application WHERE out = $job_id")
        .bind(("job_id", job_record_id))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let applications: Vec<Application> = result
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut applicants = Vec::new();
    for app in applications {
        let mut u_res = db
            .query("SELECT * FROM User WHERE id = $uid")
            .bind(("uid", app.applicant.clone()))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let users: Vec<User> = u_res.take(0).unwrap_or_default();
        if let Some(u) = users.into_iter().next() {
            applicants.push(ApplicantData {
                user: UserProfile::from(u),
                datetime_applied: app
                    .datetime_applied
                    .unwrap_or_else(|| "Unknown".to_string()), // <--- FIXED
                status: if app.status.is_empty() {
                    "Pending".to_string()
                } else {
                    app.status
                }, // <--- FIXED
            });
        }
    }

    Ok(Json(applicants))
}

pub async fn create_company(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
    Json(data): Json<CreateCompanyRequest>,
) -> Result<Json<String>, StatusCode> {
    let user = get_user_from_uid(claims.uid.clone(), &db).await?;
    let user_id = user.id.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let company = Company {
        id: None,
        created_by: user_id.clone(),
        name: data.name,
        description: data.description,
        location: data.location,
        logo: data.logo,
        website: data.website,
    };

    let mut res = db
        .query("CREATE company CONTENT $comp")
        .bind(("comp", company))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let created: Option<Company> = res.take(0).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(comp) = created {
        let comp_id = comp.id.unwrap();
        let now = chrono::Utc::now().timestamp();

        let sql = "RELATE $user->works_for->$company SET designation = $designation, employee_since = $since, is_verified = true";
        let res2 = db
            .query(sql)
            .bind(("company", comp_id))
            .bind(("user", user_id))
            .bind(("designation", data.designation))
            .bind(("since", now))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        res2.check()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json("Company created successfully".to_string()))
    } else {
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub async fn get_company(
    State(db): State<Surreal<Db>>,
    Path(company_id): Path<String>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<CompanyProfileResponse>, StatusCode> {
    let comp_rid = RecordId::from_str(&company_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let current_user = get_user_from_uid(claims.uid.clone(), &db).await?;
    let current_user_id = current_user.id.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut comp_res = db
        .query("SELECT * FROM company WHERE id = $id")
        .bind(("id", comp_rid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let comp_opt: Option<Company> = comp_res
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let company = comp_opt.ok_or(StatusCode::NOT_FOUND)?;

    let is_owner = company.created_by == current_user_id;

    let mut works_for_res = db
        .query("SELECT * FROM works_for WHERE out = $id")
        .bind(("id", comp_rid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let works_for_edges: Vec<works_for> = works_for_res.take(0).unwrap_or_default();

    let mut is_employee = false;
    let mut employees = Vec::new();

    for edge in works_for_edges {
        if edge.user == current_user_id {
            is_employee = true;
        }

        let mut u_res = db
            .query("SELECT * FROM $user")
            .bind(("user", edge.user.clone()))
            .await
            .unwrap();

        let users: Vec<User> = u_res.take(0).unwrap_or_default();
        if let Some(u) = users.into_iter().next() {
            employees.push(EmployeeData {
                user: UserProfile::from(u),
                designation: edge.designation,
                employee_since: edge.employee_since,
                is_verified: edge.is_verified,
            });
        }
    }

    Ok(Json(CompanyProfileResponse {
        company: CompanyData::from(company),
        employees,
        is_employee,
        is_owner,
    }))
}

pub async fn join_company(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
    Json(data): Json<JoinCompanyRequest>,
) -> Result<Json<String>, StatusCode> {
    let user = get_user_from_uid(claims.uid.clone(), &db).await?;
    let user_id = user.id.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let comp_rid = RecordId::from_str(&data.company_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let now = chrono::Utc::now().timestamp();

    let sql = "RELATE $user->works_for->$company SET designation = $designation, employee_since = $since, is_verified = false";
    let res = db
        .query(sql)
        .bind(("company", comp_rid))
        .bind(("user", user_id))
        .bind(("designation", data.designation))
        .bind(("since", now))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    res.check().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json("Successfully joined company".to_string()))
}

pub async fn search_companies(
    State(db): State<Surreal<Db>>,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<CompanyData>>, StatusCode> {
    let mut res = db.query("SELECT * FROM company WHERE string::lowercase(name) CONTAINS string::lowercase($q) LIMIT 10")
        .bind(("q", params.q))
        .await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let companies: Vec<Company> = res.take(0).unwrap_or_default();
    Ok(Json(companies.into_iter().map(CompanyData::from).collect()))
}

async fn get_working_at(db: &Surreal<Db>, user_id: &RecordId) -> Option<Vec<UserCompanyData>> {
    let mut res = db.query(
        "SELECT out AS company_id, out.name AS company_name, out.created_by AS creator_id, designation, is_verified FROM works_for WHERE in = $uid"
    ).bind(("uid", user_id.clone())).await.ok()?;

    let records: Vec<WorksForQueryResult> = res.take(0).ok()?;
    if records.is_empty() {
        return None;
    }

    let companies = records
        .into_iter()
        .map(|record| UserCompanyData {
            company_id: record.company_id.to_string(),
            company_name: record.company_name,
            designation: record.designation,
            is_verified: record.is_verified,
            is_owner: record.creator_id == *user_id,
        })
        .collect();

    Some(companies)
}

pub async fn verify_employee(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
    Json(data): Json<VerifyEmployeeRequest>,
) -> Result<Json<String>, StatusCode> {
    let user = get_user_from_uid(claims.uid, &db).await?;
    let user_id = user.id.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let comp_rid = RecordId::from_str(&data.company_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut comp_res = db
        .query("SELECT * FROM company WHERE id = $id AND created_by = $uid")
        .bind(("id", comp_rid.clone()))
        .bind(("uid", user_id))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let comp: Option<Company> = comp_res.take(0).unwrap_or_default();

    if comp.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let target_user_rid = RecordId::from_str(&data.user_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let res = db
        .query("UPDATE works_for SET is_verified = true WHERE in = $target AND out = $comp")
        .bind(("target", target_user_rid))
        .bind(("comp", comp_rid))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    res.check().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json("Employee verified successfully".to_string()))
}

pub async fn update_application_status(
    State(db): State<Surreal<Db>>,
    Extension(_claims): Extension<Claims>,
    Json(data): Json<UpdateApplicationStatusRequest>,
) -> Result<Json<String>, StatusCode> {
    let job_rid = RecordId::from_str(&data.job_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let applicant_rid =
        RecordId::from_str(&data.applicant_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let res = db
        .query("UPDATE application SET status = $status WHERE in = $applicant AND out = $job")
        .bind(("status", data.status))
        .bind(("applicant", applicant_rid))
        .bind(("job", job_rid))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    res.check().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json("Status updated".to_string()))
}

pub async fn get_my_applications(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<MyApplicationData>>, StatusCode> {
    let user = get_user_from_uid(claims.uid, &db).await?;
    let user_id = user.id.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut res = db
        .query("SELECT * FROM application WHERE in = $uid")
        .bind(("uid", user_id.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let apps: Vec<Application> = res.take(0).unwrap_or_default();
    let mut my_apps = Vec::new();

    for app in apps {
        let mut job_res = db
            .query("SELECT * FROM jobs WHERE id = $job_id")
            .bind(("job_id", app.out.clone()))
            .await
            .unwrap();

        let jobs: Vec<Job> = job_res.take(0).unwrap_or_default();
        if let Some(job) = jobs.into_iter().next() {
            let mut name_res = db
                .query("SELECT VALUE name FROM $eid")
                .bind(("eid", job.employer_id.clone()))
                .await
                .unwrap();
            let name: Option<String> = name_res.take(0).unwrap_or_default();

            let job_data = JobsData {
                id: job.id.unwrap().to_string(),
                employer_name: name.unwrap_or_default(),
                employer_id: job.employer_id.to_string(),
                title: job.title,
                company_name: job.company_name,
                company_id: job.company_id.clone().map(|id| id.to_string()),
                min_experience: job.min_experience,
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
                has_applied: Some(true),
                photos: job.photos,
            };
            my_apps.push(MyApplicationData {
                job: job_data,
                status: if app.status.is_empty() {
                    "Pending".to_string()
                } else {
                    app.status
                }, // <--- FIXED
                datetime_applied: app
                    .datetime_applied
                    .unwrap_or_else(|| "Unknown".to_string()), // <--- FIXED
            });
        }
    }
    Ok(Json(my_apps))
}

pub async fn get_single_job(
    State(db): State<Surreal<Db>>,
    Path(job_id): Path<String>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<JobsData>, StatusCode> {
    let job_rid = RecordId::from_str(&job_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let job: Option<Job> = db
        .select(job_rid.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let job = job.ok_or(StatusCode::NOT_FOUND)?;

    // 1. Fetch the employer's name dynamically instead of assuming the current user is the employer

    let mut result = db
        .query("SELECT VALUE name FROM $eid")
        .bind(("eid", job.employer_id.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let employer_name: Option<String> = result.take(0).unwrap_or_default();

    // 2. Check if the current user has already applied to this job
    let user = get_user_from_uid(claims.uid, &db).await?;
    let user_id = user.id.unwrap();

    let mut app_res = db
        .query("SELECT * FROM application WHERE in = $uid AND out = $jid")
        .bind(("uid", user_id))
        .bind(("jid", job_rid))
        .await
        .unwrap();
    let apps: Vec<Application> = app_res.take(0).unwrap_or_default();

    // 3. Build the final job data to send to the frontend
    let job_data = JobsData {
        id: job.id.unwrap().to_string(),
        employer_name: employer_name.unwrap_or_default(),
        employer_id: job.employer_id.to_string(),
        title: job.title,
        company_name: job.company_name,
        company_id: job.company_id.clone().map(|id| id.to_string()),
        min_experience: job.min_experience,
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
        has_applied: Some(!apps.is_empty()), // True if an application exists, False otherwise
        photos: job.photos,
    };

    Ok(Json(job_data))
}

pub async fn update_job(
    State(db): State<Surreal<Db>>,
    Path(job_id): Path<String>,
    Extension(claims): Extension<Claims>,
    Json(data): Json<UpdateJobRequest>,
) -> Result<Json<String>, StatusCode> {
    let job_rid = RecordId::from_str(&job_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let user = get_user_from_uid(claims.uid, &db).await?;
    let user_id = user.id.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let job: Option<Job> = db
        .select(job_rid.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let job = job.ok_or(StatusCode::NOT_FOUND)?;

    if job.employer_id != user_id {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Convert the incoming string data into strict DB record pointers
    let merge_data = MergeJobData::from(data);

    let res = db
        .query("UPDATE $rid MERGE $data")
        .bind(("rid", job_rid.clone()))
        .bind(("data", merge_data)) // Pass the converted struct here
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    res.check().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json("Job updated successfully".to_string()))
}

pub async fn delete_job(
    State(db): State<Surreal<Db>>,
    Path(job_id): Path<String>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<String>, StatusCode> {
    let job_rid = RecordId::from_str(&job_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let user = get_user_from_uid(claims.uid, &db).await?;
    let user_id = user.id.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let job: Option<Job> = db
        .select(job_rid.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let job = job.ok_or(StatusCode::NOT_FOUND)?;

    if job.employer_id != user_id {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let res = db
        .query("DELETE application WHERE out = $rid; DELETE $rid;")
        .bind(("rid", job_rid.clone())) // <--- FIXED: Now correctly binds the RecordId, not the String
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    res.check().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json("Job deleted successfully".to_string()))
}

pub async fn update_company(
    State(db): State<Surreal<Db>>,
    Path(company_id): Path<String>,
    Extension(claims): Extension<Claims>,
    Json(data): Json<UpdateCompanyRequest>,
) -> Result<Json<String>, StatusCode> {
    let comp_rid = RecordId::from_str(&company_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let user = get_user_from_uid(claims.uid, &db).await?;
    let user_id = user.id.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let comp: Option<Company> = db
        .select(comp_rid.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let comp = comp.ok_or(StatusCode::NOT_FOUND)?;

    if comp.created_by != user_id {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let res = db
        .query("UPDATE $rid MERGE $data")
        .bind(("rid", comp_rid.clone()))
        .bind(("data", data))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    res.check().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json("Company updated successfully".to_string()))
}

pub async fn delete_company(
    State(db): State<Surreal<Db>>,
    Path(company_id): Path<String>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<String>, StatusCode> {
    let comp_rid = RecordId::from_str(&company_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let user = get_user_from_uid(claims.uid, &db).await?;
    let user_id = user.id.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let comp: Option<Company> = db
        .select(comp_rid.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let comp = comp.ok_or(StatusCode::NOT_FOUND)?;

    if comp.created_by != user_id {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let res = db
        .query("DELETE works_for WHERE out = $rid; DELETE $rid;")
        .bind(("rid", comp_rid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    res.check().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json("Company deleted successfully".to_string()))
}

pub async fn global_search(
    State(db): State<Surreal<Db>>,
    Extension(_claims): Extension<Claims>,
    Query(params): Query<GlobalSearchQuery>,
) -> Result<Json<GlobalSearchResponse>, StatusCode> {
    let mut response = GlobalSearchResponse {
        users: vec![],
        jobs: vec![],
        companies: vec![],
    };

    let q = params.q.unwrap_or_default().to_lowercase();
    let cat = params.category.unwrap_or_else(|| "all".to_string());

    // --- SEARCH USERS ---
    if cat == "all" || cat == "users" {
        let mut sql = "SELECT * FROM User WHERE 1=1".to_string();
        if !q.is_empty() {
            sql.push_str(" AND (string::lowercase(name) CONTAINS $q OR string::lowercase(email) CONTAINS $q)");
        }
        if let Some(finding) = params.is_finding_job {
            sql.push_str(&format!(" AND is_finding_job = {}", finding));
        }
        sql.push_str(" LIMIT 20");

        let mut res = db
            .query(&sql)
            .bind(("q", q.clone()))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let users: Vec<User> = res.take(0).unwrap_or_default();
        response.users = users.into_iter().map(UserProfile::from).collect();
    }

    // --- SEARCH JOBS ---
    if cat == "all" || cat == "jobs" {
        let mut sql = "SELECT * FROM jobs WHERE 1=1".to_string();
        if !q.is_empty() {
            sql.push_str(" AND (string::lowercase(title) CONTAINS $q OR string::lowercase(description) CONTAINS $q OR string::lowercase(company_name) CONTAINS $q)");
        }
        if let Some(ref loc) = params.location {
            if !loc.is_empty() {
                sql.push_str(" AND string::lowercase(location) CONTAINS string::lowercase($loc)");
            }
        }
        sql.push_str(" ORDER BY datetime_created DESC LIMIT 20");

        let mut res = db
            .query(&sql)
            .bind(("q", q.clone()))
            .bind(("loc", params.location.clone().unwrap_or_default()))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let jobs: Vec<Job> = res.take(0).unwrap_or_default();
        for job in jobs {
            let mut name_res = db
                .query("SELECT VALUE name FROM $eid")
                .bind(("eid", job.employer_id.clone()))
                .await
                .unwrap();
            let emp_name: Option<String> = name_res.take(0).unwrap_or_default();

            response.jobs.push(JobsData {
                id: job.id.unwrap().to_string(),
                employer_name: emp_name.unwrap_or_default(),
                employer_id: job.employer_id.to_string(),
                title: job.title,
                company_name: job.company_name,
                company_id: job.company_id.map(|id| id.to_string()),
                min_experience: job.min_experience,
                description: job.description,
                skills_required: job.skills_required,
                majors_accepted: job.majors_accepted,
                location: job.location,
                is_active: job.is_active,
                salary_range_start: job.salary_range_start,
                salary_range_end: job.salary_range_end,
                datetime_created: job.datetime_created,
                datetime_due: job.datetime_due,
                min_ed_lvl: EduLevel::try_from(job.min_ed_lvl).unwrap_or(EduLevel::Bachelors),
                has_applied: None,
                photos: job.photos,
            });
        }
    }

    // --- SEARCH COMPANIES ---
    if cat == "all" || cat == "companies" {
        let mut sql = "SELECT * FROM company WHERE 1=1".to_string();
        if !q.is_empty() {
            sql.push_str(" AND (string::lowercase(name) CONTAINS $q OR string::lowercase(description) CONTAINS $q)");
        }
        if let Some(ref loc) = params.location {
            if !loc.is_empty() {
                sql.push_str(" AND string::lowercase(location) CONTAINS string::lowercase($loc)");
            }
        }
        sql.push_str(" LIMIT 20");

        let mut res = db
            .query(&sql)
            .bind(("q", q.clone()))
            .bind(("loc", params.location.clone().unwrap_or_default()))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let companies: Vec<Company> = res.take(0).unwrap_or_default();
        response.companies = companies.into_iter().map(CompanyData::from).collect();
    }

    Ok(Json(response))
}
