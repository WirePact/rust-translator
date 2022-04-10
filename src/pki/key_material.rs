use std::error::Error;
use std::path::Path;

use log::{debug, info};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Name, X509Req, X509};
use tokio::fs::{read_to_string, write};
use tonic::transport::Channel;
use tonic::Request;

use crate::grpc::wirepact::pki::pki_service_client::PkiServiceClient;
use crate::grpc::wirepact::pki::SignCsrRequest;

const CA_CERT_PATH: &str = "./ca.crt";
const KEY_PATH: &str = "./translator.key";
const CERT_PATH: &str = "./translator.crt";

pub(super) async fn load_ca(
    client: &mut PkiServiceClient<Channel>,
) -> Result<X509, Box<dyn Error>> {
    let cert_path = Path::new(CA_CERT_PATH);

    match cert_path.exists() {
        true => {
            debug!("CA certificate found, load from file system.");
            let content = read_to_string(cert_path).await?;
            let cert = X509::from_pem(content.as_bytes())?;
            Ok(cert)
        }
        false => {
            info!("CA cert does not exist, fetching from PKI.");
            let result = client.get_ca(Request::new(())).await?.into_inner();
            write(cert_path, result.certificate.as_slice()).await?;
            let cert = X509::from_pem(result.certificate.as_slice())?;
            Ok(cert)
        }
    }
}

pub(super) async fn load_key() -> Result<PKey<Private>, Box<dyn Error>> {
    let key_path = Path::new(KEY_PATH);

    match key_path.exists() {
        true => {
            debug!("Private Key found, load from file system.");
            let content = read_to_string(key_path).await?;
            let key = PKey::private_key_from_pem(content.as_bytes())?;
            Ok(key)
        }
        false => {
            info!("Private Key does not exist, creating new key.");
            let new_key = create_key()?;
            write(key_path, new_key.private_key_to_pem_pkcs8()?).await?;
            Ok(new_key)
        }
    }
}

pub(super) async fn load_cert(
    client: &mut PkiServiceClient<Channel>,
    common_name: &str,
    key: &PKey<Private>,
) -> Result<X509, Box<dyn Error>> {
    let cert_path = Path::new(CERT_PATH);

    match cert_path.exists() {
        true => {
            debug!("Certificate found, load from file system.");
            let content = read_to_string(cert_path).await?;
            let cert = X509::from_pem(content.as_bytes())?;
            Ok(cert)
        }
        false => {
            info!("Certificate does not exist, creating CSR and contact PKI.");
            let csr = create_csr(common_name, key)?;
            let result = client
                .sign_csr(Request::new(SignCsrRequest { csr: csr.to_pem()? }))
                .await?
                .into_inner();
            write(cert_path, result.certificate.as_slice()).await?;
            let cert = X509::from_pem(result.certificate.as_slice())?;
            Ok(cert)
        }
    }
}

fn create_key() -> Result<PKey<Private>, Box<dyn Error>> {
    let rsa = Rsa::generate(2048)?;
    let key = PKey::from_rsa(rsa)?;

    Ok(key)
}

fn create_csr(common_name: &str, key: &PKeyRef<Private>) -> Result<X509Req, Box<dyn Error>> {
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "WirePact PKI")?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Translator")?;
    let name = name.build();

    let mut req_builder = X509Req::builder()?;
    req_builder.set_pubkey(key)?;
    req_builder.set_version(2)?;
    req_builder.set_subject_name(name.as_ref())?;
    req_builder.sign(key, MessageDigest::sha256())?;

    Ok(req_builder.build())
}
