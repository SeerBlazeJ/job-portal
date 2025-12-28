use axum::{
    Extension, Json, Router,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    serve,
};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use surrealdb::engine::local::Db;
use surrealdb::{RecordId, Surreal, engine::local::RocksDb};
use tower_http::cors::{Any, CorsLayer};

#[derive(Deserialize)]
struct SignupData {
    uid: String,
    pword: String,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
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

#[derive(Clone, Serialize, Deserialize)]
struct User {
    id: Option<RecordId>,
    uid: String,
    pword_hash: String,
}

#[tokio::main]
async fn main() {
    let db = Surreal::new::<RocksDb>("Job_Portal")
        .await
        .expect("Failed to make a connection with the database");
    db.use_ns("main").use_db("main").await.unwrap();

    // cors layer can be removed because php can call axum server to server. But, cors layer here is added just to be on the safer side, tests with php are yet to be done.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/signup", post(signup))
        .route("/signin", post(signin));

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/profile", get(get_profile))
        .route_layer(middleware::from_fn(auth_middleware));

    // Combine them
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors)
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
        .query("SELECT * FROM User WHERE uid = $uid")
        .bind(("uid", claims.uid.clone()))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .take(0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let user = users.first().ok_or(StatusCode::NOT_FOUND)?;
    let id = user.id.clone().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(UserProfile {
        id: id.to_string(),
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
    let user = User {
        id: None,
        uid: data.uid,
        pword_hash: password_hash,
    };
    let _: Option<User> = db
        .create("User")
        .content(user)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json("User created".to_string()))
}

async fn signin(
    State(db): State<Surreal<Db>>,
    Json(data): Json<SignupData>,
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
