use std::sync::Arc;

use log::{debug, error, info};
use tonic::{Request, Response, Status};

use crate::grpc::envoy::service::auth::v3::authorization_server::Authorization;
use crate::grpc::envoy::service::auth::v3::{CheckRequest, CheckResponse};
use crate::translator::responses::{egress_ok_response, forbidden_response, noop_ok_response};
use crate::translator::Translator;
use crate::Pki;

const NO_USER_ID_REASON: &str = "No user ID found in outbound communication.";

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
            forbidden: Some(NO_USER_ID_REASON.to_string()),
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

        if let Some(reason) = egress_result.forbidden {
            if reason != NO_USER_ID_REASON {
                info!("Request is forbidden, reason: {}.", reason);
                return Ok(Response::new(forbidden_response(&reason)));
            }
        }

        if egress_result.user_id.is_none() {
            info!("Request is forbidden, reason: no user id is provided.");
            return Ok(Response::new(forbidden_response(NO_USER_ID_REASON)));
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

#[cfg(test)]
mod tests {
    use crate::grpc::envoy::service::auth::v3::check_response::HttpResponse;
    use crate::{IngressResult, WIREPACT_IDENTITY_HEADER};

    use super::*;

    const PKI_ADDRESS: &str = "http://localhost:8080";
    const GRPC_OK: i32 = 0;
    const GRPC_PERMISSION_DENIED: i32 = 7;

    struct Skip;
    #[crate::async_trait]
    impl Translator for Skip {
        async fn ingress(&self, _: &str, _: &CheckRequest) -> Result<IngressResult, Status> {
            todo!()
        }

        async fn egress(&self, _: &CheckRequest) -> Result<EgressResult, Status> {
            Ok(EgressResult::skip())
        }
    }

    struct NoUserId;
    #[crate::async_trait]
    impl Translator for NoUserId {
        async fn ingress(&self, _: &str, _: &CheckRequest) -> Result<IngressResult, Status> {
            todo!()
        }

        async fn egress(&self, _: &CheckRequest) -> Result<EgressResult, Status> {
            Ok(EgressResult::no_user_id())
        }
    }

    struct Forbidden;
    #[crate::async_trait]
    impl Translator for Forbidden {
        async fn ingress(&self, _: &str, _: &CheckRequest) -> Result<IngressResult, Status> {
            todo!()
        }

        async fn egress(&self, _: &CheckRequest) -> Result<EgressResult, Status> {
            Ok(EgressResult::forbidden("reason".to_string()))
        }
    }

    struct Allowed;
    #[crate::async_trait]
    impl Translator for Allowed {
        async fn ingress(&self, _: &str, _: &CheckRequest) -> Result<IngressResult, Status> {
            todo!()
        }

        async fn egress(&self, _: &CheckRequest) -> Result<EgressResult, Status> {
            Ok(EgressResult::allowed("userid".to_string(), None))
        }
    }

    #[tokio::test]
    async fn noop_response_on_skip() {
        let translator = Arc::new(Skip {});
        let pki = Arc::new(Pki::new(PKI_ADDRESS, "test").await.unwrap());
        let server = EgressServer::new(translator, pki);

        let request = CheckRequest { attributes: None };

        let response = server
            .check(Request::new(request))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.status.unwrap().code, GRPC_OK);
    }

    #[tokio::test]
    async fn forbidden_on_no_userid() {
        let translator = Arc::new(NoUserId {});
        let pki = Arc::new(Pki::new(PKI_ADDRESS, "test").await.unwrap());
        let server = EgressServer::new(translator, pki);

        let request = CheckRequest { attributes: None };

        let response = server
            .check(Request::new(request))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            response.status.as_ref().unwrap().code,
            GRPC_PERMISSION_DENIED
        );
        assert_eq!(response.status.as_ref().unwrap().message, NO_USER_ID_REASON);
    }

    #[tokio::test]
    async fn forbidden_on_forbidden_response() {
        let translator = Arc::new(Forbidden {});
        let pki = Arc::new(Pki::new(PKI_ADDRESS, "test").await.unwrap());
        let server = EgressServer::new(translator, pki);

        let request = CheckRequest { attributes: None };

        let response = server
            .check(Request::new(request))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            response.status.as_ref().unwrap().code,
            GRPC_PERMISSION_DENIED
        );
        assert_eq!(response.status.as_ref().unwrap().message, "reason");
    }

    #[tokio::test]
    async fn allowed() {
        let translator = Arc::new(Allowed {});
        let pki = Arc::new(Pki::new(PKI_ADDRESS, "test").await.unwrap());
        let server = EgressServer::new(translator, pki);

        let request = CheckRequest { attributes: None };

        let response = server
            .check(Request::new(request))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.status.as_ref().unwrap().code, GRPC_OK);

        if let HttpResponse::OkResponse(response) = response.http_response.unwrap() {
            let header = response.headers.get(0).unwrap().header.as_ref().unwrap();
            assert_eq!(header.key, WIREPACT_IDENTITY_HEADER);
            assert!(header.value.starts_with("ey"));
        } else {
            panic!("Unexpected response");
        }
    }
}
