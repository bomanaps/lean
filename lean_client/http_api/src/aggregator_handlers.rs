/// Admin endpoint handlers for toggling the aggregator role at runtime.
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::aggregator_controller::SharedController;

#[derive(Deserialize)]
pub(crate) struct ToggleRequest {
    enabled: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Serialize)]
struct StatusResponse {
    is_aggregator: bool,
}

#[derive(Serialize)]
struct ToggleResponse {
    is_aggregator: bool,
    previous: bool,
}

/// Handle `GET /lean/v0/admin/aggregator`.
///
/// Returns whether the node is currently acting as aggregator.
///
/// **Responses**
/// - `200 OK` — `{"is_aggregator": bool}`
/// - `503 Service Unavailable` — controller not wired (typical in test nodes)
pub async fn handle_status(State(ctrl): State<SharedController>) -> Response {
    let Some(ctrl) = ctrl else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Aggregator controller not available",
            }),
        )
            .into_response();
    };

    (
        StatusCode::OK,
        Json(StatusResponse {
            is_aggregator: ctrl.is_enabled(),
        }),
    )
        .into_response()
}

/// Handle `POST /lean/v0/admin/aggregator`.
///
/// Activates or deactivates the aggregator role at runtime so operators can
/// rotate aggregation duties across nodes without restarting.
///
/// **Request body** — JSON object:
/// - `enabled` (bool): desired aggregator state
///
/// **Responses**
/// - `200 OK` — `{"is_aggregator": bool, "previous": bool}`
/// - `400 Bad Request` — body missing, malformed, or wrong field types
/// - `503 Service Unavailable` — controller not wired
pub async fn handle_toggle(
    State(ctrl): State<SharedController>,
    body: Result<Json<ToggleRequest>, JsonRejection>,
) -> Response {
    let Some(ctrl) = ctrl else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Aggregator controller not available",
            }),
        )
            .into_response();
    };

    let Json(req) = match body {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid or malformed request body",
                }),
            )
                .into_response();
        }
    };

    let previous = ctrl.set_enabled(req.enabled).await;

    (
        StatusCode::OK,
        Json(ToggleResponse {
            is_aggregator: req.enabled,
            previous,
        }),
    )
        .into_response()
}
