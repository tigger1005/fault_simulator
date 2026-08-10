use thiserror::Error;

/// Boxed error type used to preserve the original cause of a [`SimulatorError`]
/// so callers can walk the full chain via [`std::error::Error::source`].
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Message plus optional preserved cause for a `SimulatorError` variant.
///
/// Boxed by every variant that carries one, so `SimulatorError` itself stays
/// pointer-sized instead of growing to fit the largest payload — this type is
/// on the hot path (returned per fault-injection candidate), so its size
/// directly affects `Result<_, SimulatorError>` copying cost.
#[derive(Debug)]
pub struct ErrorDetail {
    message: String,
    source: Option<BoxError>,
}

impl std::fmt::Display for ErrorDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ErrorDetail {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

/// Structured error types for the fault injection simulator.
///
/// This enum covers all error categories that can occur during
/// simulation configuration, ELF parsing, thread management,
/// and fault injection execution. Each variant carries a human-readable
/// message and, where the failure was caused by an underlying error,
/// the original error is preserved via `#[source]`.
#[derive(Error, Debug)]
pub enum SimulatorError {
    /// Configuration file read or parse error.
    #[error("Config error: {0}")]
    Config(#[source] Box<ErrorDetail>),

    /// ELF file parsing or symbol resolution error.
    #[error("ELF error: {0}")]
    Elf(#[source] Box<ErrorDetail>),

    /// Thread pool initialization or management error.
    #[error("Thread error: {0}")]
    Thread(#[source] Box<ErrorDetail>),

    /// Channel send/receive failure.
    #[error("Channel error: {0}")]
    Channel(#[source] Box<ErrorDetail>),

    /// Timeout waiting for worker thread results.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Simulation execution error (e.g. unicorn emulation failure).
    #[error("Simulation error: {0}")]
    Simulation(#[source] Box<ErrorDetail>),

    /// A worker thread panicked during execution.
    #[error("Thread panic: {0}")]
    ThreadPanic(String),
}

impl SimulatorError {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(Box::new(ErrorDetail {
            message: message.into(),
            source: None,
        }))
    }

    pub fn config_with(message: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self::Config(Box::new(ErrorDetail {
            message: message.into(),
            source: Some(source.into()),
        }))
    }

    pub fn elf(message: impl Into<String>) -> Self {
        Self::Elf(Box::new(ErrorDetail {
            message: message.into(),
            source: None,
        }))
    }

    pub fn elf_with(message: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self::Elf(Box::new(ErrorDetail {
            message: message.into(),
            source: Some(source.into()),
        }))
    }

    pub fn thread(message: impl Into<String>) -> Self {
        Self::Thread(Box::new(ErrorDetail {
            message: message.into(),
            source: None,
        }))
    }

    pub fn thread_with(message: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self::Thread(Box::new(ErrorDetail {
            message: message.into(),
            source: Some(source.into()),
        }))
    }

    pub fn channel(message: impl Into<String>) -> Self {
        Self::Channel(Box::new(ErrorDetail {
            message: message.into(),
            source: None,
        }))
    }

    pub fn channel_with(message: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self::Channel(Box::new(ErrorDetail {
            message: message.into(),
            source: Some(source.into()),
        }))
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::Timeout(message.into())
    }

    pub fn simulation(message: impl Into<String>) -> Self {
        Self::Simulation(Box::new(ErrorDetail {
            message: message.into(),
            source: None,
        }))
    }

    pub fn simulation_with(message: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self::Simulation(Box::new(ErrorDetail {
            message: message.into(),
            source: Some(source.into()),
        }))
    }

    pub fn thread_panic(message: impl Into<String>) -> Self {
        Self::ThreadPanic(message.into())
    }
}

impl From<String> for SimulatorError {
    fn from(s: String) -> Self {
        SimulatorError::simulation(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SimulatorError` is returned from hot-path functions (e.g. per fault-injection
    /// candidate), so keep it at its original size (32 bytes: a `String` payload plus
    /// discriminant). It once regressed to 40 bytes when a variant carried an unboxed
    /// `(String, Option<BoxError>)` payload, causing a measurable `cargo bench` slowdown.
    #[test]
    fn error_stays_original_size() {
        assert!(std::mem::size_of::<SimulatorError>() <= 32);
    }
}
