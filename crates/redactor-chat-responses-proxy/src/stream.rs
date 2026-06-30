use crate::http::sse_error_event;
use async_stream::stream;
use axum::body::Bytes;
use futures_util::{Stream, StreamExt};
use redactor::{RedactionSession, RestoreResult, restore_text_with_session};
use std::convert::Infallible;

#[derive(Debug, Clone)]
pub struct SseRestoreBuffer {
    session: RedactionSession,
    buffer: String,
    max_token_len: usize,
}

impl SseRestoreBuffer {
    pub fn new(session: RedactionSession) -> Self {
        let max_token_len = session
            .entries
            .iter()
            .map(|entry| entry.token.len())
            .max()
            .unwrap_or(0);
        Self {
            session,
            buffer: String::new(),
            max_token_len,
        }
    }

    pub fn push(&mut self, fragment: &str) -> Result<String, RestoreResult> {
        self.buffer.push_str(fragment);
        let keep = self.max_token_len.saturating_mul(2).max(1);
        if self.buffer.len() <= keep {
            return Ok(String::new());
        }

        let mut split_at = self.buffer.len() - keep;
        while split_at > 0 && !self.buffer.is_char_boundary(split_at) {
            split_at -= 1;
        }

        let prefix = self.buffer[..split_at].to_string();
        self.buffer = self.buffer[split_at..].to_string();
        let restored = restore_text_with_session(&prefix, &self.session);
        if restored.is_valid() {
            Ok(restored.restored_text)
        } else {
            Err(restored)
        }
    }

    pub fn finish(&mut self) -> Result<String, RestoreResult> {
        let remaining = std::mem::take(&mut self.buffer);
        let restored = restore_text_with_session(&remaining, &self.session);
        if restored.is_valid() {
            Ok(restored.restored_text)
        } else {
            Err(restored)
        }
    }
}

type StreamRestoreStep = Result<Option<Bytes>, Bytes>;

#[derive(Debug)]
struct SseStreamRestorer {
    utf8: Utf8ChunkDecoder,
    restorer: SseRestoreBuffer,
}

impl SseStreamRestorer {
    fn new(session: RedactionSession) -> Self {
        Self {
            utf8: Utf8ChunkDecoder::default(),
            restorer: SseRestoreBuffer::new(session),
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> StreamRestoreStep {
        match self.utf8.push(bytes) {
            Ok(Some(text)) => self.restore_fragment(&text),
            Ok(None) => Ok(None),
            Err(error) => Err(Bytes::from(sse_error_event(&error.to_string()))),
        }
    }

    fn flush_decoder(&mut self) -> StreamRestoreStep {
        match self.utf8.finish() {
            Ok(Some(text)) => self.restore_fragment(&text),
            Ok(None) => Ok(None),
            Err(error) => Err(Bytes::from(sse_error_event(&error.to_string()))),
        }
    }

    fn finish(&mut self) -> StreamRestoreStep {
        Self::restore_result(self.restorer.finish())
    }

    fn restore_fragment(&mut self, text: &str) -> StreamRestoreStep {
        Self::restore_result(self.restorer.push(text))
    }

    fn restore_result(result: Result<String, RestoreResult>) -> StreamRestoreStep {
        match result {
            Ok(restored) if restored.is_empty() => Ok(None),
            Ok(restored) => Ok(Some(Bytes::from(restored))),
            Err(error) => Err(Bytes::from(sse_error_event(
                &error.validation_errors.join("; "),
            ))),
        }
    }
}

pub(crate) fn restore_sse_stream<S, E>(
    stream: S,
    session: RedactionSession,
) -> impl Stream<Item = Result<Bytes, Infallible>>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: std::fmt::Display,
{
    stream! {
        let mut restorer = SseStreamRestorer::new(session);
        futures_util::pin_mut!(stream);

        while let Some(item) = stream.next().await {
            match item {
                Ok(bytes) => match restorer.push_bytes(&bytes) {
                    Ok(Some(restored)) => yield Ok::<Bytes, Infallible>(restored),
                    Ok(None) => {}
                    Err(error_event) => {
                        yield Ok::<Bytes, Infallible>(error_event);
                        return;
                    }
                },
                Err(error) => {
                    yield Ok::<Bytes, Infallible>(Bytes::from(sse_error_event(&error.to_string())));
                    return;
                }
            }
        }

        for step in [restorer.flush_decoder(), restorer.finish()] {
            match step {
                Ok(Some(restored)) => yield Ok::<Bytes, Infallible>(restored),
                Ok(None) => {}
                Err(error_event) => {
                    yield Ok::<Bytes, Infallible>(error_event);
                    return;
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct Utf8ChunkDecoder {
    pending: Vec<u8>,
}

impl Utf8ChunkDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<String>, redactor::RedactorError> {
        self.pending.extend_from_slice(bytes);
        match std::str::from_utf8(&self.pending) {
            Ok(valid) => {
                let text = valid.to_string();
                self.pending.clear();
                Ok(Some(text))
            }
            Err(error) if error.error_len().is_none() => {
                let valid_up_to = error.valid_up_to();
                if valid_up_to == 0 {
                    Ok(None)
                } else {
                    let text = std::str::from_utf8(&self.pending[..valid_up_to])
                        .map_err(|utf8_error| {
                            redactor::RedactorError::Validation(utf8_error.to_string())
                        })?
                        .to_string();
                    self.pending = self.pending[valid_up_to..].to_vec();
                    Ok(Some(text))
                }
            }
            Err(error) => Err(redactor::RedactorError::Validation(error.to_string())),
        }
    }

    pub fn finish(&mut self) -> Result<Option<String>, redactor::RedactorError> {
        if self.pending.is_empty() {
            return Ok(None);
        }

        let text = std::str::from_utf8(&self.pending)
            .map_err(|error| redactor::RedactorError::Validation(error.to_string()))?
            .to_string();
        self.pending.clear();
        Ok(Some(text))
    }
}

#[cfg(test)]
mod tests {
    use super::{SseRestoreBuffer, SseStreamRestorer};
    use redactor::{FindingKind, RedactionPolicy, RedactorBuilder};

    #[test]
    fn sse_restore_buffer_handles_split_tokens() {
        let redactor = RedactorBuilder::new()
            .with_redaction_policy(RedactionPolicy::default().with_kind(FindingKind::Domain, true))
            .build();
        let session = redactor
            .redact_with_session("domain=service.example.com")
            .expect("session");
        let token = session.entries[0].token.clone();
        let mut buffer = SseRestoreBuffer::new(session);
        let first = buffer
            .push(&format!("data: {{\"delta\":\"{}", &token[..8]))
            .expect("first push");
        let second = buffer
            .push(&(token[8..].to_string() + "\"}\n\n"))
            .expect("second push");
        let tail = buffer.finish().expect("finish");
        let combined = format!("{first}{second}{tail}");

        assert!(combined.contains("service.example.com"));
    }

    #[test]
    fn stream_restorer_emits_sse_error_for_invalid_token() {
        let redactor = RedactorBuilder::new()
            .with_redaction_policy(RedactionPolicy::default().with_kind(FindingKind::Domain, true))
            .build();
        let session = redactor
            .redact_with_session("domain=service.example.com")
            .expect("session");
        let invalid = session.entries[0].token.replace("001", "999");
        let mut restorer = SseStreamRestorer::new(session);

        assert!(
            restorer
                .push_bytes(format!("data: {invalid}\n\n").as_bytes())
                .expect("buffered")
                .is_none()
        );

        let error = restorer.finish().expect_err("restore failure");
        let message = String::from_utf8(error.to_vec()).expect("utf8 error");
        assert!(message.contains("event: error"));
        assert!(message.contains("restore_error"));
    }
}
