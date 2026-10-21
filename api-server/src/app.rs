use crate::{
    auth_http::{self, AuthHttp},
    error::ApiError,
    state::ApplicationState,
};
use actix_web::{
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    web, App, Error, HttpRequest, HttpResponse,
};
use lightning_client::model::ErrorCode;

pub fn application(
    state: ApplicationState,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = Error,
        InitError = (),
    >,
> {
    App::new()
        .app_data(web::Data::new(state))
        .wrap(AuthHttp::headers())
        .service(
            web::scope("/api/v1")
                .configure(auth_http::configure)
                .configure(crate::reads::configure)
                .configure(crate::operations::http::configure)
                .default_service(web::to(not_found)),
        )
        .default_service(web::to(not_found))
}

pub(crate) async fn not_found(
    request: HttpRequest,
    state: web::Data<ApplicationState>,
) -> Result<HttpResponse, ApiError> {
    state
        .auth
        .validate_request(&request, !request.method().is_safe())?;
    Err(ApiError::new(ErrorCode::NotFound))
}
