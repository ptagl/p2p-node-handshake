/// This module contains helper functions to setup TLS connections.
use std::{sync::Arc, time::SystemTime};

use rustls::{
    client::ServerCertVerifier, Certificate, ClientConfig, ClientConnection, PrivateKey, ServerName,
};

use crate::avalanche::P2pError;

/// Initializes a TLS connection configuration to connect to Avalanche nodes.
pub fn get_tls_connection(
    ip_address: &str,
    private_key: PrivateKey,
    certificate: Certificate,
) -> Result<ClientConnection, P2pError> {
    let server_name = ServerName::try_from(ip_address)
        .map_err(|error| P2pError::InvalidServerName(ip_address.to_string(), error.to_string()))?;

    // Prepare a basic configuration
    let config = Arc::new(
        get_default_tls_config((private_key.clone(), certificate.clone())).map_err(|error| {
            P2pError::TlsConfigurationError(ip_address.to_string(), error.to_string())
        })?,
    );

    Ok(ClientConnection::new(config, server_name).map_err(|error| {
        P2pError::TlsConfigurationError(ip_address.to_string(), error.to_string())
    }))?
}

/// Returns a basic configuration to establish a TLS connection.
/// This shouldn't be used in production as, for instance,
/// the certificate verification is disable (see [`NoCertificateVerification`]).
fn get_default_tls_config(
    (private_key, certificate): (PrivateKey, Certificate),
) -> Result<ClientConfig, String> {
    rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
        .with_client_auth_cert(vec![certificate], private_key)
        .map_err(|error| error.to_string())
}

/// Mock struct to disable the verification of TLS certificates.
/// This is needed as Avalanche nodes may have self-signed certificates.
struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    /// The [`get_tls_connection`] function expects a valid IP address as input, without the port.
    mod tls_connection {
        use crate::avalanche::{tls::get_tls_connection, P2pError};

        #[test]
        fn ip_address_with_port() {
            // Including the port after the IP is not expected and should trigger an error
            let ip_address = String::from("127.0.0.256:9651");
            let (private_key, certificate) = cert_manager::x509::generate_der(None).unwrap();

            let connection_result = get_tls_connection(&ip_address, private_key, certificate);

            assert_eq!(
                connection_result.unwrap_err(),
                P2pError::InvalidServerName(ip_address, String::from("invalid dns name"))
            );
        }

        #[test]
        fn invalid_ip_address() {
            // .257 is an invalid value
            let ip_address = String::from("127.0.0.257");
            let (private_key, certificate) = cert_manager::x509::generate_der(None).unwrap();

            let connection_result = get_tls_connection(&ip_address, private_key, certificate);

            assert_eq!(
                connection_result.unwrap_err(),
                P2pError::InvalidServerName(ip_address, String::from("invalid dns name"))
            );
        }
    }
}
