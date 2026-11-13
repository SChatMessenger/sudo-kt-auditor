//! Shared by the integration tests.

/// Stops the test with the reason when a step fails. Tests only: the
/// auditor itself returns every error (repo CLAUDE.md: fail loudly).
pub trait Must<T> {
    fn must(self) -> T;
}

impl<T, E: std::fmt::Debug> Must<T> for Result<T, E> {
    #[track_caller]
    fn must(self) -> T {
        self.unwrap_or_else(|e| panic!("{e:?}"))
    }
}

impl<T> Must<T> for Option<T> {
    #[track_caller]
    fn must(self) -> T {
        self.unwrap_or_else(|| panic!("missing value"))
    }
}
