use std::str::FromStr;

use axum::{
    Extension, Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use chrono::NaiveDateTime;
use jsonwebtoken::{DecodingKey, Validation, decode};
use surrealdb::Surreal;
use surrealdb::engine::local::Db;

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
    let id = user.id.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(UserProfile {
        id: id.to_string(),
        uid: user.uid,
        name: user.name,
        email: user.email,
        is_finding_job: user.is_finding_job,
        education: user.education,
        skills: user.skills,
    }))
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

pub async fn get_jobs(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>, // ✅ Use claims from middleware, not body
) -> Result<Json<Vec<JobsData>>, StatusCode> {
    // Use the uid from the validated token
    let (skills_vec, edu_info_vec) = get_skills_eduinfo_from_uid(claims.uid, &db).await?;

    let jobs: Vec<Job> = match (skills_vec, edu_info_vec) {
        (None, None) => db
            .query("SELECT * FROM jobs WHERE is_active = true ORDER BY rand() LIMIT 15")
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .take(0)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,

        // Case 2: Only skills exist - filter by skills
        (Some(skills), None) => db
            .query(
                "SELECT * FROM jobs
                 WHERE is_active = true
                 AND skills_required CONTAINSANY $skills
                 ORDER BY rand() LIMIT 15",
            )
            .bind(("skills", skills))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .take(0)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,

        // Case 3: Only education info exists - filter by education
        (None, Some(edu_info)) => {
            let mut all_jobs = Vec::new();

            for (edu_level, major) in edu_info {
                let jobs: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                     WHERE is_active = true
                     AND min_ed_lvl <= $edu_level
                     AND $major INSIDE majors_accepted
                     ORDER BY rand() LIMIT 15",
                    )
                    .bind(("edu_level", edu_level as i32))
                    .bind(("major", major))
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .take(0)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                all_jobs.extend(jobs);
            }

            // Shuffle and limit to 15
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            all_jobs.shuffle(&mut rng);
            all_jobs.truncate(15);
            all_jobs
        }

        // Case 4: Both skills and education info exist - filter by both
        (Some(skills), Some(edu_info)) => {
            let mut all_jobs = Vec::new();

            for (edu_level, major) in edu_info {
                let jobs: Vec<Job> = db
                    .query(
                        "SELECT * FROM jobs
                     WHERE is_active = true
                     AND skills_required CONTAINSANY $skills
                     AND min_ed_lvl <= $edu_level
                     AND $major INSIDE majors_accepted
                     ORDER BY rand() LIMIT 15",
                    )
                    .bind(("skills", skills.clone()))
                    .bind(("edu_level", edu_level as i32))
                    .bind(("major", major))
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .take(0)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                all_jobs.extend(jobs);
            }

            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            all_jobs.shuffle(&mut rng);
            all_jobs.truncate(15);
            all_jobs
        }
    };

    let database = db.clone();
    let futures = jobs.into_iter().map(|j| {
        let db = database.clone();
        async move {
            let employer_id_str = j.employer_id.to_string();
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
                id: j.id.unwrap().to_string(),
                employer_name: name.unwrap_or_default(),
                title: j.title,
                description: j.description,
                skills_required: j.skills_required,
                majors_accepted: j.majors_accepted,
                location: j.location,
                is_active: j.is_active,
                salary_range_start: j.salary_range_start,
                salary_range_end: j.salary_range_end,
                datetime_created: j.datetime_created,
                datetime_due: j.datetime_due,
                min_ed_lvl: j.min_ed_lvl,
            })
        }
    });

    let results = futures::future::join_all(futures).await;
    let jobs_data: Vec<JobsData> = results.into_iter().filter_map(|r| r.ok()).collect();

    Ok(Json(jobs_data))
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
        datetime_created: NaiveDateTime::from_str(chrono::Utc::now().to_rfc3339().as_str())
            .unwrap_or(NaiveDateTime::default()),
        datetime_due,
        min_ed_lvl: data.min_ed_lvl,
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
