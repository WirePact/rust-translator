extern crate core;

use std::error::Error;
use std::sync::Arc;

use log::{debug, info};
use tokio::try_join;
use tonic::transport::Server;
pub use tonic::{async_trait, Status};

pub use grpc::envoy::service::auth::v3::CheckRequest;
pub use translator::{
    EgressResult, IngressResult, Translator, HTTP_AUTHORIZATION_HEADER, WIREPACT_IDENTITY_HEADER,
};

use crate::pki::Pki;
use crate::translator::egress::EgressServer;
use crate::translator::ingress::IngressServer;

mod grpc;
mod pki;
mod translator;

/// TODO: Add documentation
pub struct TranslatorConfig {
    pub pki_address: String,
    pub common_name: String,
    pub ingress_port: u16,
    pub egress_port: u16,
    pub translator: Arc<dyn Translator>,
}

pub async fn run_translator(config: &TranslatorConfig) -> Result<(), Box<dyn Error>> {
    debug!("Initializing PKI.");
    let pki = Arc::new(Pki::new(&config.pki_address, &config.common_name).await?);

    let ingress_address = format!("0.0.0.0:{}", config.ingress_port);
    info!("Creating and starting ingress server @ {}", ingress_address);
    let ingress = Server::builder().add_service(
        grpc::envoy::service::auth::v3::authorization_server::AuthorizationServer::new(
            IngressServer::new(config.translator.clone(), pki.clone()),
        ),
    );

    let egress_address = format!("0.0.0.0:{}", config.egress_port);
    info!("Creating and starting egress server @ {}", egress_address);
    let egress = Server::builder().add_service(
        grpc::envoy::service::auth::v3::authorization_server::AuthorizationServer::new(
            EgressServer::new(config.translator.clone(), pki.clone()),
        ),
    );

    try_join!(
        ingress.serve_with_shutdown(ingress_address.parse()?, signal()),
        egress.serve_with_shutdown(egress_address.parse()?, signal()),
    )?;

    Ok(())
}

#[cfg(windows)]
async fn signal() {
    use tokio::signal::windows::ctrl_c;
    let mut stream = ctrl_c().unwrap();
    stream.recv().await;
    debug!("Ctrl+C received.");
    info!("Signal received. Shutting down server.");
}

#[cfg(unix)]
async fn signal() {
    use log::debug;
    use tokio::signal::unix::{signal, SignalKind};

    let mut int = signal(SignalKind::interrupt()).unwrap();
    let mut term = signal(SignalKind::terminate()).unwrap();

    tokio::select! {
        _ = int.recv() => debug!("SIGINT received."),
        _ = term.recv() => debug!("SIGTERM received."),
    }

    info!("Signal received. Shutting down server.");
}
