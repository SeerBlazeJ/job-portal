#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
        routing::post,
    };
    use serde_json::{Value, json};
    use std::str::FromStr;
    use surrealdb::{Surreal, engine::local::RocksDb};
    use tower::ServiceExt; // For `oneshot`

    // Import the required modules from your crate
    use crate::data_structures::EduLevel;
    use crate::helper_functions::{encode_jwt, hash_pword, verify_password};
    use crate::server_functions::{signin, signup};

    // ==========================================
    // UNIT TESTS: Helper Functions
    // ==========================================

    #[test]
    fn test_password_hashing() {
        let plain_password = "my_super_secret_password";

        // Test hashing
        let hash = hash_pword(plain_password).expect("Failed to hash password");
        assert_ne!(plain_password, hash); // Hash should not equal plain text

        // Test verification
        let is_valid = verify_password(plain_password, &hash).expect("Verification failed");
        assert!(is_valid, "Password should verify correctly against hash");

        // Test wrong password
        let is_invalid = verify_password("wrong_password", &hash).expect("Verification failed");
        assert!(!is_invalid, "Wrong password should not verify");
    }

    #[test]
    fn test_jwt_encoding() {
        let user_id = "user_12345".to_string();
        let token_result = encode_jwt(user_id.clone());

        assert!(token_result.is_ok(), "Failed to encode JWT");
        let token = token_result.unwrap();
        assert!(!token.is_empty(), "JWT token should not be empty");
        assert!(token.split('.').count() == 3, "JWT should have 3 parts");
    }

    // ==========================================
    // UNIT TESTS: Data Structures
    // ==========================================

    #[test]
    fn test_edu_level_parsing() {
        // Test FromStr implementation
        assert_matches::assert_matches!(
            EduLevel::from_str("SecondarySchool"),
            Ok(EduLevel::SecondarySchool)
        );
        assert_matches::assert_matches!(EduLevel::from_str("HighSchool"), Ok(EduLevel::HighSchool));
        assert_matches::assert_matches!(EduLevel::from_str("Bachelors"), Ok(EduLevel::Bachelors));
        assert!(EduLevel::from_str("InvalidLevel").is_err());

        // Test TryFrom<u8> implementation
        assert_matches::assert_matches!(EduLevel::try_from(0), Ok(EduLevel::SecondarySchool));
        assert_matches::assert_matches!(EduLevel::try_from(3), Ok(EduLevel::Bachelors));
        assert!(EduLevel::try_from(99).is_err());
    }

    // ==========================================
    // INTEGRATION TESTS: Axum Routes & Database
    // ==========================================

    // Helper function to setup a test router with an isolated temporary DB instance
    async fn setup_test_app() -> Router {
        // Create a unique temporary path for the RocksDB so parallel tests don't collide
        let temp_dir =
            std::env::temp_dir().join(format!("job_portal_test_{}", uuid::Uuid::new_v4()));
        let db = Surreal::new::<RocksDb>(temp_dir)
            .await
            .expect("Failed to create test DB");
        db.use_ns("test").use_db("test").await.unwrap();

        // Build a miniature version of the router targeting the endpoints we want to test
        Router::new()
            .route("/signup", post(signup))
            .route("/signin", post(signin))
            .with_state(db)
    }

    #[tokio::test]
    async fn test_signup_route() {
        let app = setup_test_app().await;

        let signup_payload = json!({
            "name": "Test User",
            "email": "test@example.com",
            "uid": "testuid123",
            "pword": "securepassword",
            "is_finding_job": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/signup")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(signup_payload.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Verify that the user was created successfully
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_signin_route() {
        let app = setup_test_app().await;

        // 1. Create the user first
        let signup_payload = json!({
            "name": "Jane Doe",
            "email": "jane@example.com",
            "uid": "janeuid456",
            "pword": "janepassword",
            "is_finding_job": false
        });

        let signup_req = Request::builder()
            .method("POST")
            .uri("/signup")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(signup_payload.to_string()))
            .unwrap();

        // We clone the app because `oneshot` consumes it
        let _ = app.clone().oneshot(signup_req).await.unwrap();

        // 2. Test successful sign in
        let signin_payload = json!({
            "uid": "janeuid456",
            "pword": "janepassword"
        });

        let signin_req = Request::builder()
            .method("POST")
            .uri("/signin")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(signin_payload.to_string()))
            .unwrap();

        let response = app.clone().oneshot(signin_req).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify JWT token is returned
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(
            body_json.get("token").is_some(),
            "Response should contain a JWT token"
        );

        // 3. Test failed sign in (wrong password)
        let bad_signin_payload = json!({
            "uid": "janeuid456",
            "pword": "wrongpassword"
        });

        let bad_signin_req = Request::builder()
            .method("POST")
            .uri("/signin")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(bad_signin_payload.to_string()))
            .unwrap();

        let bad_response = app.oneshot(bad_signin_req).await.unwrap();
        assert_eq!(bad_response.status(), StatusCode::UNAUTHORIZED);
    }
}
