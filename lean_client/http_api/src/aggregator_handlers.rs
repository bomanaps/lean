/// Admin endpoint handlers for toggling the aggregator role at runtime.
use axum::{
    Extension,
    body::Bytes,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use metrics::METRICS;

use crate::aggregator_controller::AggregatorControllerHandle;

/// Convenience alias used by the routing layer.
pub type SharedController = Option<AggregatorControllerHandle>;

/// Handle `GET /lean/v0/admin/aggregator`.
///
/// Returns whether the node is currently acting as aggregator.
///
/// **Responses**
/// - `200 OK` — `{"is_aggregator": bool}`
/// - `503 Service Unavailable` — controller not wired (typical in test nodes)
pub async fn handle_status(
    Extension(ctrl): Extension<SharedController>,
) -> Response {
    let Some(ctrl) = ctrl else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "Aggregator controller not available"})),
        )
            .into_response();
    };

    (StatusCode::OK, axum::Json(json!({"is_aggregator": ctrl.is_enabled()}))).into_response()
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
    Extension(ctrl): Extension<SharedController>,
    body: Bytes,
) -> Response {
    let Some(ctrl) = ctrl else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "Aggregator controller not available"})),
        )
            .into_response();
    };

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": "Invalid JSON body"})),
            )
                .into_response();
        }
    };

    let Some(enabled_val) = payload.get("enabled") else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Missing 'enabled' field in body"})),
        )
            .into_response();
    };

    // `as_bool()` returns None for JSON numbers like 0/1, rejecting them
    // explicitly as the spec requires (aggregator.py line 70).
    let Some(enabled) = enabled_val.as_bool() else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "'enabled' must be a boolean"})),
        )
            .into_response();
    };

    let previous = ctrl.set_enabled(enabled).await;

    METRICS.get().map(|m| m.lean_is_aggregator.set(if enabled { 1 } else { 0 }));

    let response_body = json!({
        "is_aggregator": enabled,
        "previous": previous,
    });

    (StatusCode::OK, axum::Json(response_body)).into_response()
}
