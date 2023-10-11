use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};

use crate::{
    handler::{
        get_me_handler, health_checker_handler, login_user_handler, logout_handler,
        register_user_handler,
    },
    jwt_auth::auth,
    AppState,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/admin/users", get(crate::handler::list_users_handler)
            .route_layer(middleware::from_fn(crate::rbac::require_admin))
            .route_layer(middleware::from_fn_with_state(app_state.clone(),auth)))
        .route("/api/healthchecker", get(health_checker_handler))
        .route("/api/auth/register", post(register_user_handler))
        .route("/api/auth/login", post(login_user_handler))
        .route("/api/auth/logout-all",post(crate::handler::logout_all_handler)
            .route_layer(middleware::from_fn_with_state(app_state.clone(),auth)))
        .route("/api/auth/refresh", post(crate::handler::refresh_handler))
        .route(
            "/api/auth/logout",
            post(logout_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/users/me",
            get(get_me_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .with_state(app_state)
}
