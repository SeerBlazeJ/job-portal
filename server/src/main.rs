mod data_structures;
mod helper_functions;
mod server_functions;
use server_functions::*;
#[cfg(test)]
mod test;

use axum::{
    Router,
    http::{Method, header},
    middleware::{self},
    routing::{get, post},
    serve,
};
use surrealdb::{Surreal, engine::local::RocksDb};
use tower_http::cors::{Any, CorsLayer};

/*
TODO:
Implement Chat System
Implement Agentic features + AI based job finding
*/

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
        .route("/signin", post(signin))
        .route("/search-companies", get(search_companies));

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/profile", get(get_profile))
        .route("/user-profile/{uid}", get(get_user_info))
        .route("/update-profile", post(update_profile))
        .route("/get-jobs", post(home))
        .route("/create-job", post(create_job))
        .route("/my-jobs", get(get_my_jobs))
        .route("/job-applicants/{job_id}", get(get_job_applicants))
        .route("/apply", post(apply_for_job))
        .route("/create-company", post(create_company))
        .route(
            "/company/{id}",
            get(get_company).put(update_company).delete(delete_company),
        )
        .route(
            "/job/{id}",
            get(get_single_job).put(update_job).delete(delete_job),
        )
        .route("/join-company", post(join_company))
        .route("/verify-employee", post(verify_employee))
        .route(
            "/update-application-status",
            post(update_application_status),
        )
        .route("/my-applications", get(get_my_applications))
        .route("/global-search", get(global_search))
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
