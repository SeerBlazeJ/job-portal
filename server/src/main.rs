mod data_structures;
mod helper_functions;
mod server_functions;
use server_functions::*;

#[cfg(test)]
mod test;

use axum::{
    Extension, // <-- Added Extension
    Router,
    http::{Method, header},
    middleware::{self},
    routing::{get, post},
    serve,
};
use std::collections::HashMap;
use std::sync::Arc;
use surrealdb::{Surreal, engine::local::RocksDb};
use tokio::sync::{RwLock, mpsc};
use tower_http::cors::{Any, CorsLayer};

// Global Tracker for Online Users
pub type ActiveUsers = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<String>>>>;

/*
 * TODO:
 * Chat system
 *Agentic AI
 */
#[tokio::main]
async fn main() {
    let db = Surreal::new::<RocksDb>("Job_Portal")
        .await
        .expect("Failed to make a connection with the database");
    db.use_ns("main").use_db("main").await.unwrap();

    let active_users: ActiveUsers = Arc::new(RwLock::new(HashMap::new()));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    let public_routes = Router::new()
        .route("/signup", post(signup))
        .route("/signin", post(signin))
        .route("/search-companies", get(search_companies))
        .route("/ws", get(ws_handler)); // WebSockets Endpoint

    let protected_routes = Router::new()
        // ... [Keep your existing protected routes here] ...
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
        // --- NEW CHAT ROUTES ---
        .route("/chat/init", post(init_chat_session))
        .route("/chat/sessions", get(get_chat_sessions))
        .route("/chat/message", post(send_message))
        .route("/chat/messages/{session_id}", get(get_chat_messages))
        // -----------------------
        .route_layer(middleware::from_fn(auth_middleware));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors)
        .layer(Extension(active_users)) // Inject WS state globally
        .with_state(db);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(listener, app).await.unwrap()
}
