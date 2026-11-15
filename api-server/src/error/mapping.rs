use crate::{auth::AuthError, journal::JournalError};
use lightning_client::model::ErrorCode;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) enum ErrorSurface {
    Api,
    Engine,
}
impl ErrorSurface {
    fn legacy_engine_code(self, api: ErrorCode, engine: ErrorCode) -> ErrorCode {
        match self {
            Self::Api => api,
            Self::Engine => engine,
        }
    }
}

// Engine conversions historically hide these details. Keep the contract explicit.
pub(crate) fn auth_error_code(error: &AuthError, surface: ErrorSurface) -> ErrorCode {
    match error {
        AuthError::NotFound => {
            surface.legacy_engine_code(ErrorCode::NotFound, ErrorCode::AuthenticationFailed)
        }
        AuthError::LastCredential => {
            surface.legacy_engine_code(ErrorCode::LastCredential, ErrorCode::AuthenticationFailed)
        }
        AuthError::EnrollmentUnavailable => surface.legacy_engine_code(
            ErrorCode::EnrollmentUnavailable,
            ErrorCode::AuthenticationFailed,
        ),
        AuthError::InvalidRequest => {
            surface.legacy_engine_code(ErrorCode::InvalidRequest, ErrorCode::AuthenticationFailed)
        }
        AuthError::Csrf => {
            surface.legacy_engine_code(ErrorCode::Csrf, ErrorCode::AuthenticationFailed)
        }
        AuthError::ReauthRequired => {
            surface.legacy_engine_code(ErrorCode::ReauthRequired, ErrorCode::AuthenticationFailed)
        }
        AuthError::Session => ErrorCode::SessionRequired,
        AuthError::Authentication => ErrorCode::AuthenticationFailed,
        AuthError::Challenge => ErrorCode::ChallengeInvalid,
        AuthError::Expired => ErrorCode::ChallengeExpired,
        AuthError::Limited | AuthError::AllocationLimited(_) => ErrorCode::RateLimited,
        AuthError::Authorization => ErrorCode::AuthorizationInvalid,
        AuthError::NotRequired => ErrorCode::AuthorizationNotRequired,
        AuthError::Storage => ErrorCode::StorageUnavailable,
    }
}

pub(crate) fn journal_error_detail(
    error: JournalError,
    surface: ErrorSurface,
) -> (ErrorCode, Option<Uuid>) {
    let (code, id) = match error {
        JournalError::NotFound => (ErrorCode::NotFound, None),
        JournalError::IdempotencyConflict(id) => (
            surface.legacy_engine_code(
                ErrorCode::IdempotencyConflict,
                ErrorCode::StorageUnavailable,
            ),
            Some(id),
        ),
        JournalError::ResourceBusy(id) => (
            surface.legacy_engine_code(ErrorCode::ResourceBusy, ErrorCode::StorageUnavailable),
            Some(id),
        ),
        JournalError::AlreadyPaid(id) => (
            surface.legacy_engine_code(ErrorCode::AlreadyPaid, ErrorCode::StorageUnavailable),
            Some(id),
        ),
        JournalError::NotReviewable => (
            surface.legacy_engine_code(
                ErrorCode::OperationNotReviewable,
                ErrorCode::StorageUnavailable,
            ),
            None,
        ),
        JournalError::ReviewExpired => (
            surface.legacy_engine_code(ErrorCode::ReviewExpired, ErrorCode::StorageUnavailable),
            None,
        ),
        JournalError::Revoked => (ErrorCode::SessionRequired, None),
        JournalError::ResponseTooLarge => (
            surface.legacy_engine_code(ErrorCode::InternalError, ErrorCode::StorageUnavailable),
            None,
        ),
        JournalError::Storage | JournalError::Secret => (ErrorCode::StorageUnavailable, None),
    };
    (
        code,
        match surface {
            ErrorSurface::Api => id,
            ErrorSurface::Engine => None,
        },
    )
}
