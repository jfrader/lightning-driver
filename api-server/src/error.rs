use crate::{auth::AuthError, journal::JournalError};
use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use lightning_client::model::{ErrorCode, ErrorDetail, ErrorOutcome};
use serde::Serialize;
use std::fmt;
use uuid::Uuid;

pub(crate) mod mapping;
use mapping::{auth_error_code, journal_error_detail, ErrorSurface};

#[derive(Debug)]
pub struct ApiError {
    pub code: ErrorCode,
    pub operation_id: Option<Uuid>,
    pub outcome: ErrorOutcome,
    retry_after: Option<u64>,
    availability_reason: Option<lightning_client::model::CapabilityReason>,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

impl ApiError {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            operation_id: None,
            outcome: ErrorOutcome::NotDispatched,
            retry_after: None,
            availability_reason: None,
        }
    }
    fn message(&self) -> &'static str {
        if let Some(reason) = self.availability_reason {
            return match reason {
                lightning_client::model::CapabilityReason::PermissionDenied => "permission_denied",
                lightning_client::model::CapabilityReason::NotConfigured => "not_configured",
                _ => "unsupported",
            };
        }
        match self.code {
            ErrorCode::SessionRequired => "Sign in required.",
            ErrorCode::Csrf => "Reload the session.",
            ErrorCode::Origin => "Request origin is not allowed.",
            ErrorCode::AuthenticationFailed => "Authentication failed.",
            ErrorCode::ChallengeExpired => "Authentication challenge expired. Start again.",
            ErrorCode::ChallengeInvalid => "Authentication challenge is invalid or consumed.",
            ErrorCode::LastCredential => "Keep at least one sign-in method.",
            ErrorCode::ReauthRequired => "Sign in again to continue.",
            ErrorCode::EnrollmentUnavailable => "Enrollment is not available.",
            ErrorCode::RateLimited => "Too many requests. Wait before starting again.",
            ErrorCode::ReadOnly => "This node is read-only.",
            ErrorCode::NotFound => "Resource not found.",
            ErrorCode::UnsupportedMediaType => "Use application/json.",
            ErrorCode::InvalidRequest => "Invalid request.",
            ErrorCode::StorageUnavailable => "Protected storage unavailable.",
            ErrorCode::AuthorizationInvalid => "Operation authorization is invalid or consumed.",
            ErrorCode::AuthorizationNotRequired => {
                "This operation does not require reauthentication."
            }
            ErrorCode::IdempotencyConflict => {
                "This request key belongs to a different operation request."
            }
            ErrorCode::ResourceBusy => "A conflicting operation is unresolved. Check its status.",
            ErrorCode::AlreadyPaid => "This payment is already settled.",
            ErrorCode::ReviewExpired => "Review expired. Start again.",
            ErrorCode::OperationNotReviewable => "This operation cannot be confirmed.",
            _ => "Request could not be completed. Check its status before taking another action.",
        }
    }
}

impl ApiError {
    pub(crate) fn unsupported(reason: Option<lightning_client::model::CapabilityReason>) -> Self {
        Self {
            availability_reason: reason,
            ..Self::new(ErrorCode::Unsupported)
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self.code {
            ErrorCode::SessionRequired | ErrorCode::AuthenticationFailed => {
                StatusCode::UNAUTHORIZED
            }
            ErrorCode::Origin | ErrorCode::Csrf | ErrorCode::ReadOnly => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::InvalidRequest | ErrorCode::InvalidCursor => StatusCode::BAD_REQUEST,
            ErrorCode::CursorExpired => StatusCode::GONE,
            ErrorCode::StorageUnavailable
            | ErrorCode::NodeOffline
            | ErrorCode::NotConfigured
            | ErrorCode::NodeAuthError => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::UpstreamInvalidResponse => StatusCode::BAD_GATEWAY,
            ErrorCode::InvalidAmount
            | ErrorCode::InvalidAddress
            | ErrorCode::InvalidPeer
            | ErrorCode::InvalidInvoice
            | ErrorCode::InvoiceExpired
            | ErrorCode::PolicyViolation
            | ErrorCode::NetworkMismatch => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::CONFLICT,
        }
    }
    fn error_response(&self) -> HttpResponse {
        let mut response = HttpResponse::build(self.status_code());
        response.insert_header(("Cache-Control", "no-store"));
        if self.code == ErrorCode::RateLimited {
            crate::observability::Event::RateLimited {
                scope: "api",
                retry_after_seconds: Some(self.retry_after.unwrap_or(60)),
            }
            .emit();
            response.insert_header(("Retry-After", self.retry_after.unwrap_or(60).to_string()));
        }
        response.json(ErrorEnvelope {
            error: ErrorDetail {
                code: self.code,
                message: self.message().into(),
                request_id: Uuid::new_v4(),
                operation_id: self.operation_id,
                outcome: self.outcome,
            },
        })
    }
}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        let mut api_error = Self::new(auth_error_code(&error, ErrorSurface::Api));
        if let AuthError::AllocationLimited(seconds) = error {
            api_error.retry_after = Some(seconds);
        }
        api_error
    }
}

impl From<JournalError> for ApiError {
    fn from(error: JournalError) -> Self {
        let (code, id) = journal_error_detail(error, ErrorSurface::Api);
        Self {
            code,
            operation_id: id,
            outcome: ErrorOutcome::NotDispatched,
            retry_after: None,
            availability_reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_limit_keeps_retry_after_and_message() {
        for seconds in [0, 17] {
            let error = ApiError::from(AuthError::AllocationLimited(seconds));
            assert_eq!(error.code, ErrorCode::RateLimited);
            assert_eq!(error.retry_after, Some(seconds));
            assert_eq!(
                error.message(),
                "Too many requests. Wait before starting again."
            );
            assert_eq!(
                error
                    .error_response()
                    .headers()
                    .get("Retry-After")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                seconds.to_string()
            );
        }
    }
}
