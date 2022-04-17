use std::sync::Arc;

use tonic::Status;

use wirepact_translator::{
    run_translator, CheckRequest, EgressResult, IngressResult, Translator, TranslatorConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_translator(&TranslatorConfig {
        pki_address: "http://pki:8080".to_string(),
        common_name: "demo translator".to_string(),
        ingress_port: 50051,
        egress_port: 50052,
        translator: Arc::new(TestTranslator {}),
    })
    .await?;

    Ok(())
}

struct TestTranslator {}

#[wirepact_translator::async_trait]
impl Translator for TestTranslator {
    async fn ingress(&self, _subject_id: &str, _: &CheckRequest) -> Result<IngressResult, Status> {
        // Fetch user information based on the subject ID and return
        // an Ingress Result.
        // This function gets called when incoming communication happens.
        todo!()
    }

    async fn egress(&self, _request: &CheckRequest) -> Result<EgressResult, Status> {
        // Fetch user information based on the subject ID and return
        // an Egress Result.
        // This function gets called when outbound communication happens.
        todo!()
    }
}
