use crate::{auth_http::AuthHttp, error::ApiError, journal::Journal, operations::Engine};
use lightning_client::{model::ErrorCode, settings::Settings};
use std::sync::Arc;

#[derive(Clone)]
pub struct ApplicationState {
    pub auth: AuthHttp,
    pub journal: Journal,
    pub registry: Arc<crate::registry::Registry>,
    pub snapshots: crate::pagination::Snapshots,
    pub(crate) engine: Engine,
}

impl ApplicationState {
    pub(crate) fn limits(&self) -> &lightning_client::settings::Limits {
        self.auth.limits()
    }
    pub async fn new(settings: &Settings, journal: Journal) -> Result<Self, ApiError> {
        settings
            .validate()
            .map_err(|_| ApiError::new(ErrorCode::NotConfigured))?;
        let auth = AuthHttp::new(settings.api.clone(), journal.clone())?;
        let mut registry = crate::registry::Registry::new(settings)
            .map_err(|_| ApiError::new(ErrorCode::NotConfigured))?;
        let mut engine =
            Engine::from_settings(settings, &registry, journal.clone(), auth.manager.clone())
                .await?;
        for node in &settings.nodes {
            if let Some(code) = engine.unavailable(&node.id) {
                registry.mark_unavailable(&node.id, code);
            }
        }
        let registry = Arc::new(registry);
        engine.attach_reads(Arc::clone(&registry));
        Ok(Self {
            auth,
            journal,
            registry,
            snapshots: crate::pagination::Snapshots::new(settings.api.limits.clone()),
            engine,
        })
    }
}
