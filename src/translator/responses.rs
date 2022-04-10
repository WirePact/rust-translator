use crate::grpc::envoy::config::core::v3::{HeaderValue, HeaderValueOption};
use crate::grpc::envoy::r#type::v3::HttpStatus;
use crate::grpc::envoy::service::auth::v3::check_response::HttpResponse;
use crate::grpc::envoy::service::auth::v3::{CheckResponse, DeniedHttpResponse, OkHttpResponse};
use crate::grpc::google::rpc::Status;
use crate::translator::WIREPACT_IDENTITY_HEADER;

const GRPC_OK: i32 = 0;
const GRPC_PERMISSION_DENIED: i32 = 7;
const HTTP_FORBIDDEN: i32 = 403;

#[allow(deprecated)]
pub(crate) fn noop_ok_response() -> CheckResponse {
    CheckResponse {
        status: Some(Status {
            code: GRPC_OK,
            message: "".to_string(),
            details: vec![],
        }),
        dynamic_metadata: None,
        http_response: Some(HttpResponse::OkResponse(OkHttpResponse {
            headers: vec![],
            headers_to_remove: vec![],
            dynamic_metadata: None,
            response_headers_to_add: vec![],
            query_parameters_to_set: vec![],
            query_parameters_to_remove: vec![],
        })),
    }
}

pub(crate) fn forbidden_response(reason: &str) -> CheckResponse {
    CheckResponse {
        status: Some(Status {
            code: GRPC_PERMISSION_DENIED,
            message: reason.to_string(),
            details: vec![],
        }),
        dynamic_metadata: None,
        http_response: Some(HttpResponse::DeniedResponse(DeniedHttpResponse {
            status: Some(HttpStatus {
                code: HTTP_FORBIDDEN,
            }),
            headers: vec![],
            body: reason.to_string(),
        })),
    }
}

#[allow(deprecated)]
pub(crate) fn ingress_ok_response(
    headers_to_add: Vec<HeaderValue>,
    headers_to_remove: Vec<String>,
) -> CheckResponse {
    let mut headers_to_remove = headers_to_remove;
    headers_to_remove.push(WIREPACT_IDENTITY_HEADER.to_string());

    let headers = headers_to_add
        .into_iter()
        .map(|h| HeaderValueOption {
            header: Some(h),
            append: None,
            append_action: 0,
        })
        .collect();

    CheckResponse {
        status: Some(Status {
            code: GRPC_OK,
            message: "".to_string(),
            details: vec![],
        }),
        dynamic_metadata: None,
        http_response: Some(HttpResponse::OkResponse(OkHttpResponse {
            headers,
            headers_to_remove,
            dynamic_metadata: None,
            response_headers_to_add: vec![],
            query_parameters_to_set: vec![],
            query_parameters_to_remove: vec![],
        })),
    }
}

#[allow(deprecated)]
pub(crate) fn egress_ok_response(jwt: &str, headers_to_remove: Vec<String>) -> CheckResponse {
    CheckResponse {
        status: Some(Status {
            code: GRPC_OK,
            message: "".to_string(),
            details: vec![],
        }),
        dynamic_metadata: None,
        http_response: Some(HttpResponse::OkResponse(OkHttpResponse {
            headers: vec![HeaderValueOption {
                header: Some(HeaderValue {
                    key: WIREPACT_IDENTITY_HEADER.to_string(),
                    value: jwt.to_string(),
                }),
                append: None,
                append_action: 0,
            }],
            headers_to_remove,
            dynamic_metadata: None,
            response_headers_to_add: vec![],
            query_parameters_to_set: vec![],
            query_parameters_to_remove: vec![],
        })),
    }
}
