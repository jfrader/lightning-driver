use crate::{
    auth_http::{self, AuthHttp},
    error::ApiError,
};
use actix_web::{
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    web, App, Error, HttpRequest, HttpResponse,
};
use lightning_client::model::ErrorCode;

pub fn application(
    auth: AuthHttp,
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
        .app_data(web::Data::new(auth))
        .wrap(AuthHttp::headers())
        .service(
            web::scope("/api/v1")
                .configure(auth_http::configure)
                .default_service(web::to(not_found)),
        )
        .default_service(web::to(not_found))
}

async fn not_found(
    request: HttpRequest,
    auth: web::Data<AuthHttp>,
) -> Result<HttpResponse, ApiError> {
    auth.validate_request(&request, !request.method().is_safe())?;
    Err(ApiError::new(ErrorCode::NotFound))
}
