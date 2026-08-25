#![forbid(unsafe_code)]

pub mod frame;
pub mod messages;
pub mod session;

pub use frame::{default_max_frame, read_envelope, write_envelope, IpcError};
pub use messages::{Envelope, PROTOCOL_VERSION};
pub use session::{SessionError, WorkerSupervisor};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::messages::{envelope, Hello};

    #[tokio::test]
    async fn roundtrip_hello() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut client = client;
        let mut server = server;
        let env = Envelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: "r1".into(),
            kind: Some(envelope::Kind::Hello(Hello {
                worker_kind: "research".into(),
                python_version: "3.13.5".into(),
            })),
        };
        write_envelope(&mut client, &env, default_max_frame())
            .await
            .unwrap();
        let got = read_envelope(&mut server, default_max_frame())
            .await
            .unwrap();
        assert_eq!(got.request_id, "r1");
    }

    #[tokio::test]
    async fn rejects_oversized_declared_length() {
        use tokio::io::AsyncWriteExt;
        let (mut client, server) = tokio::io::duplex(1024);
        let mut server = server;
        let huge: u32 = 4 * 1024 * 1024 + 1;
        client.write_all(&huge.to_be_bytes()).await.unwrap();
        let err = read_envelope(&mut server, default_max_frame())
            .await
            .unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge { .. }));
    }
}
