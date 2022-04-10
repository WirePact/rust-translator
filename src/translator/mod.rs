pub use tonic::Status;

pub use egress::EgressResult;
pub use ingress::IngressResult;

use crate::grpc::envoy::service::auth::v3::CheckRequest;

pub(crate) mod egress;
pub(crate) mod ingress;
mod responses;

/// Name of the custom HTTP header that is used by WirePact
/// to identify the signed JWT.
pub const WIREPACT_IDENTITY_HEADER: &str = "x-wirepact-identity";

/// Name of the default HTTP authorization header.
pub const HTTP_AUTHORIZATION_HEADER: &str = "authorization";

/// Translator for ingress and egress communication. This trait
/// is used in the respective gRPC servers to translate authentication
/// data into a signed JWT and vice versa.
#[tonic::async_trait]
pub trait Translator: Send + Sync {
    /// Inbound communication translator. Used to transform a signed JWT
    /// (if any) into the corresponding authentication data. If no JWT
    /// is available or no [subject_id] can be parsed, the method will
    /// not be called and the [IngressResult] will be [IngressResult::forbidden].
    async fn ingress(
        &self,
        subject_id: &str,
        request: &CheckRequest,
    ) -> Result<IngressResult, Status>;

    /// Outbound communication translator. Used to transform the authentication
    /// data into a signed JWT that contains the users ID.
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
