use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::AlgorithmParameters::RSA;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse, RSAKeyParameters};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use log::debug;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

use crate::grpc::wirepact::pki::pki_service_client::PkiServiceClient;
use crate::pki::key_material::{load_ca, load_cert, load_key};

mod key_material;

const JWT_AUDIENCE: &str = "WirePact";

#[derive(Debug)]
pub(crate) struct Pki {
    common_name: String,
    ca_cert: X509,
    cert: X509,
    key: PKey<Private>,
}

impl Pki {
    /// Create and initialize the PKI by fetching the CA certificate if
    /// needed and creating/loading a local private key with the
    /// certificate. If no local certificate is present, a new one
    /// is created via CSR from the CA.
    pub(crate) async fn new(pki_address: &str, common_name: &str) -> Result<Self, Box<dyn Error>> {
        let mut grpc_client = PkiServiceClient::connect(pki_address.to_string()).await?;

        let ca_cert = load_ca(&mut grpc_client).await?;
        let key = load_key().await?;
        let cert = load_cert(&mut grpc_client, common_name, &key).await?;
        let common_name = common_name.to_string();

        Ok(Self {
            common_name,
            ca_cert,
            key,
            cert,
        })
    }

    /// Create a signed JWT for the given user id.
    /// The JWT is signed with the private RSA key (RS256) from the key material.
    /// Additionally, the ["x5c"](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6)
    /// and ["x5t#S256"](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8)
    /// headers are attached to the JWT as they are required by WirePact to
    /// verify the certificate chain on sent JWTs.
    /// The audience is always set to "WirePact".
    pub(crate) fn create_signed_jwt(&self, user_id: &str) -> Result<String, Box<dyn Error>> {
        debug!("Creating signed JWT for user {}", user_id);

        let rsa_key = self.key.rsa()?;

        let mut jwk = Jwk {
            common: Default::default(),
            algorithm: RSA(RSAKeyParameters {
                key_type: Default::default(),
                n: base64::encode_config(rsa_key.n().to_vec(), base64::URL_SAFE_NO_PAD),
                e: base64::encode_config(rsa_key.e().to_vec(), base64::URL_SAFE_NO_PAD),
            }),
        };
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);

        let mut header = Header::new(Algorithm::RS256);
        header.x5t_s256 = Some(self.x5t_s256()?);
        header.x5c = Some(self.x5c()?);
        header.jwk = Some(jwk);

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let payload = Claims {
            aud: JWT_AUDIENCE.to_string(),
            iat: timestamp.as_secs() as usize,
            exp: (timestamp.as_secs() + 60) as usize,
            iss: self.common_name.clone(),
            sub: user_id.to_string(),
        };

        let key = EncodingKey::from_rsa_der(self.key.private_key_to_der()?.as_slice());

        Ok(encode(&header, &payload, &key)?)
    }

    /// Return the user id (subject) from the given JWT.
    /// This validates the x5c and x5t headers against the own
    /// downloaded CA certificate from the PKI.
    pub(crate) fn get_subject_from_jwt(&self, jwt: &str) -> Result<String, Box<dyn Error>> {
        debug!("Extracting subject from JWT and validate JWT.");
        let header = decode_header(jwt)?;
        let jwk = header.jwk.as_ref().ok_or("No JWK header found.")?;
        let params = match &jwk.algorithm {
            RSA(params) => params,
            _ => return Err("no RSA params sent with jwt.".into()),
        };

        // TODO: check certificate chain. however, this may not be used anymore since
        // we use mTLS later on with envoy which basically checks the certificate
        // chain.
        // let certificate_chain = &header
        //     .x5c_der()?
        //     .ok_or("No Certificate Chain in JWT.")?
        //     .iter()
        //     .map(|cert| X509::from_der(cert.as_slice()).unwrap())
        //     .collect::<Vec<X509>>();
        //
        // let mut store = X509StoreBuilder::new()?;
        // for cert in certificate_chain {
        //     store.add_cert(cert.clone())?;
        // }
        // let store = store.build();
        // store.
        //
        // println!("{:#?}", certificate_chain);

        let key = DecodingKey::from_rsa_components(&params.n, &params.e)?;
        let token = decode::<Claims>(jwt, &key, &Validation::new(Algorithm::RS256))?;

        debug!(
            "Valid JWT found. Extracted subject id: {}.",
            token.claims.sub
        );
        Ok(token.claims.sub)
    }

    fn x5t_s256(&self) -> Result<String, Box<dyn Error>> {
        let hash = self.cert.digest(MessageDigest::sha256())?;
        Ok(base64::encode_config(hash, base64::STANDARD_NO_PAD))
    }

    fn x5c(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let cert_hash = self.cert.to_der()?;
        let ca_hash = self.ca_cert.to_der()?;

        Ok(vec![
            base64::encode_config(cert_hash, base64::STANDARD_NO_PAD),
            base64::encode_config(ca_hash, base64::STANDARD_NO_PAD),
        ])
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String,
    exp: usize,
    iat: usize,
    iss: String,
    sub: String,
}
