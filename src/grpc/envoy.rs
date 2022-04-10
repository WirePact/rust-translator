pub(crate) mod service {
    pub(crate) mod auth {
        pub(crate) mod v3 {
            tonic::include_proto!("envoy.service.auth.v3");
        }
    }
}

pub(crate) mod config {
    pub(crate) mod core {
        pub(crate) mod v3 {
            tonic::include_proto!("envoy.config.core.v3");
        }
    }
}

pub(crate) mod r#type {
    pub(crate) mod v3 {
        tonic::include_proto!("envoy.r#type.v3");
    }
}
