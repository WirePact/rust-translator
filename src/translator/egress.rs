use std::sync::Arc;

use log::{debug, error, info};
use tonic::{Request, Response, Status};

use crate::grpc::envoy::service::auth::v3::authorization_server::Authorization;
use crate::grpc::envoy::service::auth::v3::{CheckRequest, CheckResponse};
use crate::translator::responses::{egress_ok_response, forbidden_response, noop_ok_response};
use crate::translator::Translator;
use crate::Pki;

const NO_USER_ID_REASON: &str = "No user id found in outbound communication.";

/// Struct that contains the egress result for the [Translator::egress] method.
/// Used by the respective constructors to signal a specific result to Envoy.
pub struct EgressResult {
    skip: bool,
    forbidden: Option<String>,
    headers_to_remove: Vec<String>,
    user_id: Option<String>,
}

impl EgressResult {
    /// Indicates that the request should be skipped (i.e. just forwarded to the destination
    /// without interfering).
    pub fn skip() -> Self {
        Self {
            skip: true,
            forbidden: None,
            headers_to_remove: Vec::new(),
            user_id: None,
        }
    }

    /// Indicates that the request should be forbidden with a given reason.
    pub fn forbidden(reason: String) -> Self {
        Self {
            skip: false,
            forbidden: Some(reason),
            headers_to_remove: Vec::new(),
            user_id: None,
        }
    }

    /// Indicates that the request should be forbidden since no user ID is given.
    pub fn no_user_id() -> Self {
        Self {
            skip: false,
            forbidden: Some("No UserID given for outbound communication.".to_string()),
            headers_to_remove: Vec::new(),
            user_id: None,
        }
    }

    /// Indicates that the request is allowed with the given user ID and
    /// an optional list of headers that should be removed before the request is
    /// sent to the destination.
    pub fn allowed(user_id: String, headers_to_remove: Option<Vec<String>>) -> Self {
        Self {
            skip: false,
            forbidden: None,
            headers_to_remove: match headers_to_remove {
                Some(headers) => headers,
                None => Vec::new(),
            },
            user_id: Some(user_id),
        }
    }
}

pub(crate) struct EgressServer {
    translator: Arc<dyn Translator>,
    pki: Arc<Pki>,
}

impl EgressServer {
    pub(crate) fn new(translator: Arc<dyn Translator>, pki: Arc<Pki>) -> Self {
        Self { translator, pki }
    }
}

#[tonic::async_trait]
impl Authorization for EgressServer {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        debug!("Received egress check request.");

        let egress_result = self.translator.egress(request.get_ref()).await?;

        if egress_result.skip {
            debug!("Skipping egress request.");
            return Ok(Response::new(noop_ok_response()));
        }

        if egress_result.user_id.is_none() {
            info!("Request is forbidden, reason: no user id is provided.");
            return Ok(Response::new(forbidden_response(NO_USER_ID_REASON)));
        }

        if let Some(reason) = egress_result.forbidden {
            info!("Request is forbidden, reason: {}.", reason);
            return Ok(Response::new(forbidden_response(&reason)));
        }

        let user_id = egress_result.user_id.unwrap();
        let jwt = self.pki.create_signed_jwt(&user_id).map_err(|e| {
            error!(
                "Failed to create signed JWT for user id '{}': {}.",
                user_id, e
            );
            Status::internal("Failed to create signed JWT.")
        })?;

        debug!("Egress request is allowed for user id {}.", user_id);
        Ok(Response::new(egress_ok_response(
            &jwt,
            egress_result.headers_to_remove,
        )))
    }
}
