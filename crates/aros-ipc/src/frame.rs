use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::messages::{Envelope, DEFAULT_MAX_FRAME_BYTES, PROTOCOL_VERSION};

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame exceeds max {max} bytes (got {got})")]
    FrameTooLarge { max: u32, got: u32 },
    #[error("protobuf decode failed")]
    Decode,
    #[error("unsupported protocol version {0}")]
    Protocol(u32),
    #[error("empty envelope kind")]
    EmptyKind,
}

pub async fn write_envelope<W: AsyncWrite + Unpin>(
    writer: &mut W,
    env: &Envelope,
    max_frame: u32,
) -> Result<(), IpcError> {
    let mut buf = BytesMut::new();
    env.encode(&mut buf).map_err(|_| IpcError::Decode)?;
    let len = buf.len() as u32;
    if len > max_frame {
        return Err(IpcError::FrameTooLarge {
            max: max_frame,
            got: len,
        });
    }
    let mut header = BytesMut::with_capacity(4);
    header.put_u32(len);
    writer.write_all(&header).await?;
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_envelope<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_frame: u32,
) -> Result<Envelope, IpcError> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let mut h = &header[..];
    let len = h.get_u32();
    if len > max_frame {
        return Err(IpcError::FrameTooLarge {
            max: max_frame,
            got: len,
        });
    }
    if len == 0 {
        return Err(IpcError::Decode);
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    let env = Envelope::decode(payload.as_slice()).map_err(|_| IpcError::Decode)?;
    if env.protocol_version != PROTOCOL_VERSION {
        return Err(IpcError::Protocol(env.protocol_version));
    }
    if env.kind.is_none() {
        return Err(IpcError::EmptyKind);
    }
    Ok(env)
}

pub fn validate_hello(env: &Envelope) -> Result<(), IpcError> {
    if env.protocol_version != PROTOCOL_VERSION {
        return Err(IpcError::Protocol(env.protocol_version));
    }
    Ok(())
}

pub const fn default_max_frame() -> u32 {
    DEFAULT_MAX_FRAME_BYTES
}
