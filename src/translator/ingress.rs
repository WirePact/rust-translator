use std::sync::Arc;

use log::{debug, error, info};
use tonic::{Request, Response, Status};

use crate::grpc::envoy::config::core::v3::HeaderValue;
use crate::grpc::envoy::service::auth::v3::authorization_server::Authorization;
use crate::grpc::envoy::service::auth::v3::{CheckRequest, CheckResponse};
use crate::translator::responses::{forbidden_response, ingress_ok_response, noop_ok_response};
use crate::translator::{Translator, WIREPACT_IDENTITY_HEADER};
use crate::Pki;

/// Struct that contains the ingress result for the [Translator::ingress] method.
/// Used by the respective constructors to signal a specific result to Envoy.
pub struct IngressResult {
    skip: bool,
    forbidden: Option<String>,
    headers_to_add: Vec<HeaderValue>,
    headers_to_remove: Vec<String>,
}

impl IngressResult {
    /// Indicates that the request should be skipped (i.e. just forwarded to the destination
    /// without interfering).
    pub fn skip() -> Self {
        Self {
            skip: true,
            forbidden: None,
            headers_to_add: Vec::new(),
            headers_to_remove: Vec::new(),
        }
    }

    /// Indicates that the request should be forbidden with a given reason.
    pub fn forbidden(reason: String) -> Self {
        Self {
            skip: false,
            forbidden: Some(reason),
            headers_to_add: Vec::new(),
            headers_to_remove: Vec::new(),
        }
    }

    /// Indicates that the request is allowed and should be forwarded to the upstream.
    /// May contain an optional list of headers (key/value pairs) that should be added to the
    /// request and an optional list of headers that should be removed from the request.
    pub fn allowed(
        headers_to_add: Option<Vec<(String, String)>>,
        headers_to_remove: Option<Vec<String>>,
    ) -> Self {
        Self {
            skip: false,
            forbidden: None,
            headers_to_add: match headers_to_add {
                Some(headers) => headers
                    .into_iter()
                    .map(|(key, value)| HeaderValue { key, value })
                    .collect(),
                None => Vec::new(),
            },
            headers_to_remove: match headers_to_remove {
                Some(headers) => headers,
                None => Vec::new(),
            },
        }
    }
}

pub(crate) struct IngressServer {
    translator: Arc<dyn Translator>,
    pki: Arc<Pki>,
}

impl IngressServer {
    pub(crate) fn new(translator: Arc<dyn Translator>, pki: Arc<Pki>) -> Self {
        Self { translator, pki }
    }
}

#[tonic::async_trait]
impl Authorization for IngressServer {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        debug!("Received ingress check request.");

        let request = request.get_ref();
        let wirepact_jwt = self
            .translator
            .get_header(request, WIREPACT_IDENTITY_HEADER)?;

        if wirepact_jwt.is_none() {
            debug!("Skipping. No wirepact JWT found in request.");
            // There is no wirepact JWT, so we can't do anything.
            return Ok(Response::new(noop_ok_response()));
        }

        let wirepact_jwt = wirepact_jwt.unwrap();
        let subject = self.pki.get_subject_from_jwt(&wirepact_jwt).map_err(|e| {
            error!("Failed to parse signed JWT: {}.", e);
            Status::internal("Failed to parse signed JWT.")
        })?;

        let ingress_result = self.translator.ingress(&subject, request).await?;

        if ingress_result.skip {
            debug!("Skipping ingress request.");
            return Ok(Response::new(noop_ok_response()));
        }

        if let Some(reason) = ingress_result.forbidden {
            info!("Request is forbidden, reason: {}.", reason);
            return Ok(Response::new(forbidden_response(&reason)));
        }

        debug!("Ingress request is allowed.");
        Ok(Response::new(ingress_ok_response(
            ingress_result.headers_to_add,
            ingress_result.headers_to_remove,
        )))
    }
}
