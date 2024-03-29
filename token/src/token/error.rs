use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to open process: {0}")]
    FailedToOpenProcess(u32),

    #[error("Failed to open process token: {0}")]
    FailedToOpenProcessToken(u32),

    #[error("Failed to duplicate token: {0}")]
    FailedToDuplicateToken(u32),

    #[error("Failed to logon a user on to the local computer: {0}")]
    FailedToLogonUser(u32),

    #[error("Failed to impersonate the security context of a logged-on user: {0}")]
    FailedToImpersonateLoggedOnUser(u32),

    #[error("Failed to lookup token privilege value: {0}")]
    FailedToLookupPrivilegeValue(u32),

    #[error("Failed to adjust token privileges: {0}")]
    FailedToAdjustTokenPrivileges(u32),

    #[error("Failed to revert to self: {0}")]
    FailedToRevertToSelf(u32),

    #[error("Failed to create named pipe: {0}")]
    FailedToCreateNamedPipe(u32),

    #[error("Failed to connect to named pipe: {0}")]
    FailedToConnectNamedPipe(u32),

    #[error("Failed to read from named pipe: {0}")]
    FailedToReadFromNamedPipe(u32),

    #[error("Failed to impersonate named pipe client: {0}")]
    ImpersonateNamedPipeClient(u32),

    #[error("Failed to open thread token: {0}")]
    FailedToOpenThreadToken(u32),

    #[error("Failed to get duplicate thread token: {0}")]
    FailedToDuplicateThreadToken(u32),

    #[error("Failed to create process with token: {0}")]
    FailedToCreateProcessWithTokenW(u32),
}
