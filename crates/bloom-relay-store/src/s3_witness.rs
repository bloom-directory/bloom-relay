//! Restore witness in S3, outside both the database and the host.
//!
//! The bucket is versioned with Object Lock, so a restored database or a
//! rolled-back host can neither rewind nor erase an earlier revision. Writes
//! are conditional on the ETag last read (`If-Match`), or on the object being
//! absent (`If-None-Match: *`), so concurrent writers never lower it.
//!
//! Credentials always come from the instance role. DNS workers keep their
//! own narrower IAM users in a shared credentials file, which the default
//! chain would otherwise pick up for this client as well.

use crate::restore::{RemoteRevision, RemoteWitness, RemoteWrite, WitnessFuture, parse_revision};
use aws_sdk_s3::{
    Client,
    error::{ProvideErrorMetadata, SdkError},
    primitives::ByteStream,
    types::ChecksumAlgorithm,
};
use std::io;

const BUCKET_ENV: &str = "BLOOM_RELAY_RESTORE_WITNESS_S3_BUCKET";
const KEY_ENV: &str = "BLOOM_RELAY_RESTORE_WITNESS_S3_KEY";
const REGION_ENV: &str = "BLOOM_RELAY_RESTORE_WITNESS_S3_REGION";

pub struct S3Witness {
    client: Client,
    bucket: String,
    key: String,
}

impl S3Witness {
    pub fn new(client: Client, bucket: String, key: String) -> Self {
        Self {
            client,
            bucket,
            key,
        }
    }

    /// Configured from `BLOOM_RELAY_RESTORE_WITNESS_S3_{BUCKET,KEY,REGION}`,
    /// or `None` when no bucket is set. A bucket without its key or region is
    /// a configuration error, never a silent fallback to the local witness.
    pub async fn from_env() -> io::Result<Option<Self>> {
        let Some(bucket) = non_empty(BUCKET_ENV) else {
            if non_empty(KEY_ENV).is_some() || non_empty(REGION_ENV).is_some() {
                return Err(invalid(format!(
                    "{KEY_ENV} and {REGION_ENV} require {BUCKET_ENV}"
                )));
            }
            return Ok(None);
        };
        let key = non_empty(KEY_ENV)
            .ok_or_else(|| invalid(format!("{BUCKET_ENV} requires {KEY_ENV}")))?;
        let region = non_empty(REGION_ENV)
            .ok_or_else(|| invalid(format!("{BUCKET_ENV} requires {REGION_ENV}")))?;
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .credentials_provider(
                aws_config::imds::credentials::ImdsCredentialsProvider::builder().build(),
            )
            .load()
            .await;
        Ok(Some(Self::new(Client::new(&config), bucket, key)))
    }
}

impl RemoteWitness for S3Witness {
    fn read(&self) -> WitnessFuture<'_, Option<RemoteRevision>> {
        Box::pin(async move {
            let response = match self
                .client
                .get_object()
                .bucket(&self.bucket)
                .key(&self.key)
                .send()
                .await
            {
                Ok(response) => response,
                Err(SdkError::ServiceError(error)) if error.err().is_no_such_key() => {
                    return Ok(None);
                }
                Err(error) => return Err(unavailable("read", error)),
            };
            let version_tag = response
                .e_tag()
                .ok_or_else(|| invalid("S3 witness response has no ETag".into()))?
                .to_owned();
            let body = response
                .body
                .collect()
                .await
                .map_err(|error| io::Error::other(format!("read S3 witness body: {error}")))?
                .into_bytes();
            Ok(Some(RemoteRevision {
                revision: parse_revision(&body)?,
                version_tag,
            }))
        })
    }

    fn write<'a>(
        &'a self,
        revision: u64,
        replacing: Option<&'a RemoteRevision>,
    ) -> WitnessFuture<'a, RemoteWrite> {
        Box::pin(async move {
            let request = self
                .client
                .put_object()
                .bucket(&self.bucket)
                .key(&self.key)
                .content_type("text/plain")
                // Object Lock buckets require an integrity checksum on writes.
                .checksum_algorithm(ChecksumAlgorithm::Sha256)
                .body(ByteStream::from(format!("{revision}\n").into_bytes()));
            let request = match replacing {
                Some(current) => request.if_match(&current.version_tag),
                None => request.if_none_match("*"),
            };
            match request.send().await {
                Ok(response) => Ok(RemoteWrite::Written(RemoteRevision {
                    revision,
                    version_tag: response
                        .e_tag()
                        .ok_or_else(|| invalid("S3 witness write returned no ETag".into()))?
                        .to_owned(),
                })),
                // 412: the object changed or appeared since it was read.
                // 409: a concurrent conditional write to the same key.
                Err(SdkError::ServiceError(error))
                    if matches!(error.raw().status().as_u16(), 409 | 412) =>
                {
                    Ok(RemoteWrite::Conflict)
                }
                Err(error) => Err(unavailable("write", error)),
            }
        })
    }
}

fn non_empty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn unavailable<E: ProvideErrorMetadata + std::fmt::Debug, R>(
    operation: &str,
    error: SdkError<E, R>,
) -> io::Error {
    let code = error.code().unwrap_or("unknown").to_owned();
    io::Error::other(format!("S3 witness {operation} failed: {code}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::{
        operation::{get_object::GetObjectOutput, put_object::PutObjectOutput},
        types::error::NoSuchKey,
    };
    use aws_smithy_mocks::{RuleMode, mock, mock_client};
    use aws_smithy_runtime_api::{http::Response as HttpResponse, http::StatusCode};
    use aws_smithy_types::body::SdkBody;

    fn witness(client: Client) -> S3Witness {
        S3Witness::new(client, "bucket".into(), "relay-1/revision".into())
    }

    #[tokio::test]
    async fn reads_revision_and_etag_and_treats_a_missing_object_as_absent() {
        let present = mock!(Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .e_tag("\"v1\"")
                .body(ByteStream::from_static(b"42\n"))
                .build()
        });
        let client = mock_client!(aws_sdk_s3, [&present]);
        assert_eq!(
            witness(client).read().await.unwrap(),
            Some(RemoteRevision {
                revision: 42,
                version_tag: "\"v1\"".into()
            })
        );

        let missing = mock!(Client::get_object).then_error(|| {
            aws_sdk_s3::operation::get_object::GetObjectError::NoSuchKey(
                NoSuchKey::builder().build(),
            )
        });
        let client = mock_client!(aws_sdk_s3, [&missing]);
        assert_eq!(witness(client).read().await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_malformed_body_fails_closed() {
        let garbage = mock!(Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .e_tag("\"v1\"")
                .body(ByteStream::from_static(b"not a revision"))
                .build()
        });
        let client = mock_client!(aws_sdk_s3, [&garbage]);
        assert!(witness(client).read().await.is_err());
    }

    #[tokio::test]
    async fn writes_are_conditional_on_the_version_read() {
        let replace = mock!(Client::put_object)
            .match_requests(|request| {
                request.if_match() == Some("\"v1\"")
                    && request.if_none_match().is_none()
                    && request.checksum_algorithm() == Some(&ChecksumAlgorithm::Sha256)
            })
            .then_output(|| PutObjectOutput::builder().e_tag("\"v2\"").build());
        let create = mock!(Client::put_object)
            .match_requests(|request| {
                request.if_none_match() == Some("*") && request.if_match().is_none()
            })
            .then_output(|| PutObjectOutput::builder().e_tag("\"v0\"").build());
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, [&replace, &create]);
        let witness = witness(client);
        let current = RemoteRevision {
            revision: 41,
            version_tag: "\"v1\"".into(),
        };
        assert_eq!(
            witness.write(42, Some(&current)).await.unwrap(),
            RemoteWrite::Written(RemoteRevision {
                revision: 42,
                version_tag: "\"v2\"".into()
            })
        );
        assert_eq!(
            witness.write(1, None).await.unwrap(),
            RemoteWrite::Written(RemoteRevision {
                revision: 1,
                version_tag: "\"v0\"".into()
            })
        );
    }

    #[tokio::test]
    async fn a_lost_race_is_a_conflict_and_other_failures_are_errors() {
        for (status, conflict) in [(412, true), (409, true), (403, false), (500, false)] {
            let rule = mock!(Client::put_object).then_http_response(move || {
                HttpResponse::new(StatusCode::try_from(status).unwrap(), SdkBody::empty())
            });
            let client = mock_client!(aws_sdk_s3, [&rule]);
            let result = witness(client).write(7, None).await;
            if conflict {
                assert_eq!(result.unwrap(), RemoteWrite::Conflict, "status {status}");
            } else {
                assert!(result.is_err(), "status {status}");
            }
        }
    }
}
