//! Signs allocation receipts with the relay's Ed25519 receipt key.
//!
//! The key is either a local 32-byte seed (tests, development) or an AWS KMS
//! key (`ECC_NIST_EDWARDS25519`), whose private half never leaves KMS. Either
//! way, every signature is verified against the public key before it is
//! returned, and an expected public key (the one Signers pin) can be required
//! at startup, so a misconfigured key fails loudly instead of issuing
//! receipts nobody trusts.
//!
//! Configuration:
//! - `BLOOM_RELAY_RECEIPT_KMS_KEY_ARN`: sign with this KMS key, with
//!   credentials only from the instance role; or
//! - `BLOOM_RELAY_RECEIPT_KEY_PATH`: a file holding the 32-byte seed;
//! - optional `BLOOM_RELAY_RECEIPT_PUBLIC_KEY_HEX`: the public key the key must
//!   have.

use aws_sdk_kms::{
    Client,
    primitives::Blob,
    types::{KeySpec, KeyUsageType, MessageType, SigningAlgorithmSpec},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::{env, fs};

const KMS_KEY_ENV: &str = "BLOOM_RELAY_RECEIPT_KMS_KEY_ARN";
const KEY_PATH_ENV: &str = "BLOOM_RELAY_RECEIPT_KEY_PATH";
const EXPECTED_PUBLIC_ENV: &str = "BLOOM_RELAY_RECEIPT_PUBLIC_KEY_HEX";

/// DER SubjectPublicKeyInfo prefix for an Ed25519 public key (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

type Error = Box<dyn std::error::Error + Send + Sync>;

pub enum ReceiptSigner {
    Local(SigningKey),
    Kms {
        client: Client,
        key_arn: String,
        public: VerifyingKey,
    },
}

impl ReceiptSigner {
    pub async fn from_env() -> Result<Self, Error> {
        let signer = match env::var(KMS_KEY_ENV).ok().filter(|v| !v.is_empty()) {
            Some(key_arn) => {
                let region = kms_region(&key_arn)?;
                let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_config::Region::new(region))
                    .credentials_provider(
                        aws_config::imds::credentials::ImdsCredentialsProvider::builder().build(),
                    )
                    .load()
                    .await;
                Self::kms(Client::new(&config), key_arn).await?
            }
            None => {
                let bytes = fs::read(env::var(KEY_PATH_ENV)?)?;
                let seed: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| "receipt key must be 32 raw bytes")?;
                Self::Local(SigningKey::from_bytes(&seed))
            }
        };
        if let Some(expected) = env::var(EXPECTED_PUBLIC_ENV).ok().filter(|v| !v.is_empty()) {
            let actual = hex::encode(signer.public_key().to_bytes());
            if actual != expected.trim().to_ascii_lowercase() {
                return Err(format!(
                    "receipt key's public key {actual} is not the expected {expected}"
                )
                .into());
            }
        }
        Ok(signer)
    }

    /// A KMS-backed signer, after checking the key is an Ed25519 signing key.
    pub async fn kms(client: Client, key_arn: String) -> Result<Self, Error> {
        let output = client
            .get_public_key()
            .key_id(&key_arn)
            .send()
            .await
            .map_err(|error| format!("KMS GetPublicKey failed: {error}"))?;
        if output.key_spec() != Some(&KeySpec::EccNistEdwards25519)
            || output.key_usage() != Some(&KeyUsageType::SignVerify)
        {
            return Err("receipt KMS key must be an ECC_NIST_EDWARDS25519 signing key".into());
        }
        let der = output
            .public_key()
            .ok_or("KMS returned no public key")?
            .as_ref();
        let raw: [u8; 32] = der
            .strip_prefix(&ED25519_SPKI_PREFIX[..])
            .and_then(|raw| raw.try_into().ok())
            .ok_or("KMS public key is not an Ed25519 SubjectPublicKeyInfo")?;
        Ok(Self::Kms {
            client,
            key_arn,
            public: VerifyingKey::from_bytes(&raw)?,
        })
    }

    pub fn public_key(&self) -> VerifyingKey {
        match self {
            Self::Local(key) => key.verifying_key(),
            Self::Kms { public, .. } => *public,
        }
    }

    pub async fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        let signature = match self {
            Self::Local(key) => key.sign(message),
            Self::Kms {
                client, key_arn, ..
            } => {
                let output = client
                    .sign()
                    .key_id(key_arn)
                    .message(Blob::new(message))
                    .message_type(MessageType::Raw)
                    .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
                    .send()
                    .await
                    .map_err(|error| format!("KMS Sign failed: {error}"))?;
                let bytes = output
                    .signature()
                    .ok_or("KMS returned no signature")?
                    .as_ref();
                Signature::from_slice(bytes)?
            }
        };
        self.public_key().verify(message, &signature)?;
        Ok(signature.to_bytes())
    }
}

/// The region in a KMS key ARN: `arn:aws:kms:<region>:<account>:key/<id>`.
fn kms_region(key_arn: &str) -> Result<String, Error> {
    let parts: Vec<&str> = key_arn.split(':').collect();
    match parts.as_slice() {
        ["arn", _, "kms", region, _, key] if !region.is_empty() && key.starts_with("key/") => {
            Ok((*region).to_owned())
        }
        _ => Err(format!("{KMS_KEY_ENV} must be a KMS key ARN").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_kms::operation::{get_public_key::GetPublicKeyOutput, sign::SignOutput};
    use aws_smithy_mocks::{RuleMode, mock, mock_client};

    const ARN: &str = "arn:aws:kms:eu-central-1:123456789012:key/abcd";

    fn spki(key: &SigningKey) -> Vec<u8> {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(key.verifying_key().as_bytes());
        der
    }

    #[test]
    fn region_comes_from_the_key_arn() {
        assert_eq!(kms_region(ARN).unwrap(), "eu-central-1");
        assert!(kms_region("alias/receipt").is_err());
        assert!(kms_region("arn:aws:s3:::bucket").is_err());
    }

    #[tokio::test]
    async fn kms_signatures_verify_with_the_kms_public_key() {
        // Stand in for KMS with a local key: KMS's Ed25519 is plain RFC 8032.
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let public = spki(&key);
        let message = b"allocation receipt bytes";
        let expected = key.sign(message).to_bytes();
        let get = mock!(Client::get_public_key).then_output(move || {
            GetPublicKeyOutput::builder()
                .key_spec(KeySpec::EccNistEdwards25519)
                .key_usage(KeyUsageType::SignVerify)
                .public_key(Blob::new(public.clone()))
                .build()
        });
        let sign = mock!(Client::sign)
            .match_requests(|request| {
                request.message_type() == Some(&MessageType::Raw)
                    && request.signing_algorithm() == Some(&SigningAlgorithmSpec::Ed25519Sha512)
                    && request.key_id() == Some(ARN)
            })
            .then_output(move || SignOutput::builder().signature(Blob::new(expected)).build());
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, [&get, &sign]);
        let signer = ReceiptSigner::kms(client, ARN.into()).await.unwrap();
        assert_eq!(signer.public_key(), key.verifying_key());
        assert_eq!(signer.sign(message).await.unwrap(), expected);
    }

    #[tokio::test]
    async fn a_signature_that_does_not_verify_is_refused() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let other = SigningKey::from_bytes(&[10u8; 32]);
        let public = spki(&key);
        let forged = other.sign(b"receipt").to_bytes();
        let get = mock!(Client::get_public_key).then_output(move || {
            GetPublicKeyOutput::builder()
                .key_spec(KeySpec::EccNistEdwards25519)
                .key_usage(KeyUsageType::SignVerify)
                .public_key(Blob::new(public.clone()))
                .build()
        });
        let sign = mock!(Client::sign)
            .then_output(move || SignOutput::builder().signature(Blob::new(forged)).build());
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, [&get, &sign]);
        let signer = ReceiptSigner::kms(client, ARN.into()).await.unwrap();
        assert!(signer.sign(b"receipt").await.is_err());
    }

    #[tokio::test]
    async fn only_ed25519_signing_keys_are_accepted() {
        let get = mock!(Client::get_public_key).then_output(|| {
            GetPublicKeyOutput::builder()
                .key_spec(KeySpec::EccNistP256)
                .key_usage(KeyUsageType::SignVerify)
                .public_key(Blob::new(vec![0u8; 91]))
                .build()
        });
        let client = mock_client!(aws_sdk_kms, [&get]);
        assert!(ReceiptSigner::kms(client, ARN.into()).await.is_err());
    }
}
