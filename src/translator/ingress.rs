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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::grpc::envoy::service::auth::v3::attribute_context::HttpRequest;
    use crate::grpc::envoy::service::auth::v3::check_response::HttpResponse;
    use crate::grpc::envoy::service::auth::v3::{attribute_context, AttributeContext};
    use crate::{EgressResult, EgressServer, IngressResult, WIREPACT_IDENTITY_HEADER};

    use super::*;

    const PKI_ADDRESS: &str = "http://localhost:8080";
    const GRPC_OK: i32 = 0;
    const GRPC_PERMISSION_DENIED: i32 = 7;

    struct Egress;
    #[crate::async_trait]
    impl Translator for Egress {
        async fn ingress(&self, _: &str, _: &CheckRequest) -> Result<IngressResult, Status> {
            todo!()
        }

        async fn egress(&self, _: &CheckRequest) -> Result<EgressResult, Status> {
            Ok(EgressResult::allowed("userid".to_string(), None))
        }
    }

    struct Skip;
    #[crate::async_trait]
    impl Translator for Skip {
        async fn ingress(&self, _: &str, _: &CheckRequest) -> Result<IngressResult, Status> {
            Ok(IngressResult::skip())
        }

        async fn egress(&self, _: &CheckRequest) -> Result<EgressResult, Status> {
            todo!()
        }
    }

    struct Forbidden;
    #[crate::async_trait]
    impl Translator for Forbidden {
        async fn ingress(&self, _: &str, _: &CheckRequest) -> Result<IngressResult, Status> {
            Ok(IngressResult::forbidden("reason".to_string()))
        }

        async fn egress(&self, _: &CheckRequest) -> Result<EgressResult, Status> {
            todo!()
        }
    }

    struct Allowed;
    #[crate::async_trait]
    impl Translator for Allowed {
        async fn ingress(&self, _: &str, _: &CheckRequest) -> Result<IngressResult, Status> {
            Ok(IngressResult::allowed(None, None))
        }

        async fn egress(&self, _: &CheckRequest) -> Result<EgressResult, Status> {
            todo!()
        }
    }

    fn create_request(jwt: Option<String>) -> CheckRequest {
        let mut headers = HashMap::new();
        if let Some(jwt) = jwt {
            headers.insert(WIREPACT_IDENTITY_HEADER.to_string(), jwt);
        }

        CheckRequest {
            attributes: Some(AttributeContext {
                source: None,
                destination: None,
                context_extensions: Default::default(),
                metadata_context: None,
                request: Some(attribute_context::Request {
                    time: None,
                    http: Some(HttpRequest {
                        id: "".to_string(),
                        method: "".to_string(),
                        headers,
                        path: "".to_string(),
                        host: "".to_string(),
                        scheme: "".to_string(),
                        query: "".to_string(),
                        fragment: "".to_string(),
                        size: 0,
                        protocol: "".to_string(),
                        body: "".to_string(),
                        raw_body: vec![],
                    }),
                }),
            }),
        }
    }

    async fn get_jwt(pki: Arc<Pki>) -> String {
        let translator = Arc::new(Egress {});
        let server = EgressServer::new(translator, pki);
        let request = CheckRequest { attributes: None };

        let response = server
            .check(Request::new(request))
            .await
            .unwrap()
            .into_inner();

        if let HttpResponse::OkResponse(response) = response.http_response.unwrap() {
            let header = response.headers.get(0).unwrap().header.as_ref().unwrap();
            return header.value.clone();
        } else {
            panic!("Unexpected response");
        }
    }

    #[tokio::test]
    async fn noop_response_on_no_header() {
        let translator = Arc::new(Skip {});
        let pki = Arc::new(Pki::new(PKI_ADDRESS, "test").await.unwrap());
        let server = IngressServer::new(translator, pki);

        let response = server
            .check(Request::new(create_request(None)))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.status.as_ref().unwrap().code, GRPC_OK);
    }

    #[tokio::test]
    async fn error_on_unparseable_jwt() {
        let translator = Arc::new(Skip {});
        let pki = Arc::new(Pki::new(PKI_ADDRESS, "test").await.unwrap());
        let server = IngressServer::new(translator, pki);

        let response = server
            .check(Request::new(create_request(Some("foobar".to_string()))))
            .await;

        assert!(response.is_err());
    }

    #[tokio::test]
    async fn noop_response_on_skip() {
        let pki = Arc::new(Pki::new(PKI_ADDRESS, "test").await.unwrap());
        let server = IngressServer::new(Arc::new(Skip {}), pki.clone());
        let jwt = get_jwt(pki).await;
        let request = create_request(Some(jwt));

        let response = server
            .check(Request::new(request))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.status.as_ref().unwrap().code, GRPC_OK);
    }

    #[tokio::test]
    async fn forbidden() {
        let pki = Arc::new(Pki::new(PKI_ADDRESS, "test").await.unwrap());
        let server = IngressServer::new(Arc::new(Forbidden {}), pki.clone());
        let jwt = get_jwt(pki).await;
        let request = create_request(Some(jwt));

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
        let pki = Arc::new(Pki::new(PKI_ADDRESS, "test").await.unwrap());
        let server = IngressServer::new(Arc::new(Allowed {}), pki.clone());
        let jwt = get_jwt(pki).await;
        let request = create_request(Some(jwt));

        let response = server
            .check(Request::new(request))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.status.as_ref().unwrap().code, GRPC_OK);
    }
}
