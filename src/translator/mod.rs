pub use tonic::Status;

pub use egress::EgressResult;
pub use ingress::IngressResult;

use crate::grpc::envoy::service::auth::v3::CheckRequest;

pub(crate) mod egress;
pub(crate) mod ingress;
mod responses;

pub const WIREPACT_IDENTITY_HEADER: &str = "x-wirepact-identity";
pub const HTTP_AUTHORIZATION_HEADER: &str = "authorization";

#[tonic::async_trait]
pub trait Translator: Send + Sync {
    async fn ingress(
        &self,
        subject_id: &str,
        request: &CheckRequest,
    ) -> Result<IngressResult, Status>;

    async fn egress(&self, request: &CheckRequest) -> Result<EgressResult, Status>;

    fn get_header(
        &self,
        request: &CheckRequest,
        header_name: &str,
    ) -> Result<Option<String>, Status> {
        let attributes = request
            .attributes
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("attributes not found"))?;
        let inner_request = attributes
            .request
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("request not found"))?;
        let http = inner_request
            .http
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("http not found"))?;

        Ok(http.headers.get(header_name).cloned())
    }
}
