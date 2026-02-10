mod data_structures;
mod helper_functions;
mod server_functions;
use server_functions::*;

use axum::{
    Router,
    http::{Method, header},
    middleware::{self},
    routing::{get, post},
    serve,
};
use surrealdb::{Surreal, engine::local::RocksDb};
use tower_http::cors::{Any, CorsLayer};

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
        .route("/update-profile", post(update_profile))
        .route("/get-jobs", post(get_jobs))
        .route("/create-job", post(create_job))
        .route_layer(middleware::from_fn(auth_middleware));

    // Combine them
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors)
        .with_state(db);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Couldn't lock port 3000 of localhost");
    serve(listener, app).await.unwrap()
}
