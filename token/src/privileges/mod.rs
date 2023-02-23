//Credits: https://github.com/zblurx/impersonate-rs/blob/main/src/utils/impersonate.rs
//This will be used later to get the token of the all processes running on the system later
use windows_sys::Win32::{
    Foundation::HANDLE,
    Security::{
        SecurityAnonymous, SecurityDelegation, SecurityIdentification, SecurityImpersonation,
        TOKEN_TYPE,
    },
    System::SystemServices::{
        SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID,
        SECURITY_MANDATORY_PROTECTED_PROCESS_RID, SECURITY_MANDATORY_SYSTEM_RID,
        SECURITY_MANDATORY_UNTRUSTED_RID,
    },
};

#[derive(Debug, Clone)]
pub struct Token {
    pub handle: HANDLE,
    pub process_id: u32,
    pub process_name: String,
    pub session_id: u32,
    pub username: String,
    pub token_type: TOKEN_TYPE,
    pub token_impersonation: ImpersonationLevel,
    pub token_integrity: IntegrityLevel,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
#[repr(i32)]
pub enum ImpersonationLevel {
    Impersonation = SecurityImpersonation,
    Delegation = SecurityDelegation,
    Anonymous = SecurityAnonymous,
    Identification = SecurityIdentification,
}

impl ImpersonationLevel {
    #[allow(dead_code)]
    pub fn display_str(&self) -> &'static str {
        match self {
            ImpersonationLevel::Impersonation => "Impersonation",
            ImpersonationLevel::Delegation => "Delegation",
            ImpersonationLevel::Anonymous => "Anonymous",
            ImpersonationLevel::Identification => "Identification",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
#[repr(i32)]
pub enum IntegrityLevel {
    Untrusted = SECURITY_MANDATORY_UNTRUSTED_RID,
    Low = SECURITY_MANDATORY_LOW_RID,
    Medium = SECURITY_MANDATORY_MEDIUM_RID,
    //MediumPlus       = SECURITY_MANDATORY_MEDIUM_PLUS_RID,
    High = SECURITY_MANDATORY_HIGH_RID,
    System = SECURITY_MANDATORY_SYSTEM_RID,
    ProtectedProcess = SECURITY_MANDATORY_PROTECTED_PROCESS_RID,
}

impl IntegrityLevel {
    #[allow(dead_code)]
    pub fn display_str(&self) -> &'static str {
        match self {
            IntegrityLevel::Untrusted => "Untrusted",
            IntegrityLevel::Low => "Low",
            IntegrityLevel::Medium => "Medium",
            //IntegrityLevel::MediumPlus          => "MediumPlus",
            IntegrityLevel::High => "High",
            IntegrityLevel::System => "System",
            IntegrityLevel::ProtectedProcess => "ProtectedProcess",
        }
    }
}
