use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    serve, Extension, Json, Router,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use surrealdb::engine::local::Db;
use surrealdb::{engine::local::RocksDb, Surreal};

#[derive(Deserialize)]
struct SignupData {
    uid: String,
    pword: String,
}
#[derive(Serialize)]
struct UserProfile {
    id: String,
    uid: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Claims {
    uid: String,
    exp: usize,
    iat: usize,
}

#[derive(Serialize, Deserialize)]
struct User {
    id: Option<String>,
    uid: String,
    pword_hash: String,
}

#[tokio::main]
async fn main() {
    let db = Surreal::new::<RocksDb>("Job_Portal")
        .await
        .expect("Failed to make a connection with the database");
    db.use_ns("main").use_db("main").await.unwrap();
    let app = Router::new()
        //Public Routes
        .route("/signup", post(signup))
        .route("/signin", post(signin))
        //Private Routes
        .route("/profile", get(get_profile))
        .route_layer(middleware::from_fn(auth_middleware))
        .with_state(db);

    let listener = tokio::net::TcpListener::bind("localhost:3000")
        .await
        .expect("Couldn't lock port 3000 of localhost");
    serve(listener, app).await.unwrap()
}

async fn get_profile(
    State(db): State<Surreal<Db>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<UserProfile>, StatusCode> {
    let users: Vec<User> = db
        .query("SELECT * FROM Users WHERE uid = $uid")
        .bind(("uid", claims.uid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let user = users.first().ok_or(StatusCode::NOT_FOUND)?;
    let id = user.id.clone().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(UserProfile {
        id,
        uid: user.uid.clone(),
    }))
}

fn hash_pword(pword: &str) -> Result<String, bcrypt::BcryptError> {
    hash(pword, DEFAULT_COST)
}

fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

fn encode_jwt(uid: String) -> Result<String, StatusCode> {
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

async fn signup(
    State(db): State<Surreal<Db>>,
    Json(data): Json<SignupData>,
) -> Result<Json<String>, StatusCode> {
    let password_hash = hash_pword(&data.pword).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _: Option<User> = db
        .create("Users")
        .content(User {
            id: None,
            uid: data.uid,
            pword_hash: password_hash,
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json("User created".to_string()))
}

async fn signin(
    State(db): State<Surreal<Db>>,
    Json(data): Json<SignupData>,
) -> Result<Json<String>, StatusCode> {
    let user_details_vec: Vec<User> = db
        .query("SELECT * FROM Users where uid=$uid")
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
            Ok(Json(jwt_token))
        }
        false => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn auth_middleware(mut req: Request, next: Next) -> Result<Response, StatusCode> {
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
