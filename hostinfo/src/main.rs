use hostinfo::{get_username, get_hostname, get_domain_name, get_internal_ip, get_process_name, get_process_id, get_parent_process_id, get_process_architecture, get_process_integrity, is_elevated};
use uuid::Uuid;

mod hostinfo;

fn main() {
    env_logger::init();
    let id = Uuid::new_v4();
    let username = get_username().unwrap();
    let hostname = get_hostname().unwrap();
    let domain_name = get_domain_name().unwrap();
    let internal_ip = get_internal_ip().unwrap();
    let process_name = get_process_name().unwrap();
    let process_id = get_process_id().to_string();
    let parent_process_id = get_parent_process_id().unwrap().to_string();
    let process_architecture = get_process_architecture().unwrap();
    let process_integrity = get_process_integrity().unwrap();
    let agent_is_elevated = is_elevated().unwrap();

    log::info!("ID: {}", id);
    log::info!("Username: {}", username);
    log::info!("Hostname: {}", hostname);
    log::info!("Domain: {}", domain_name);
    log::info!("IP: {}", internal_ip);
    log::info!("Process: {}", process_name);
    log::info!("PID: {}", process_id);
    log::info!("PPID: {}", parent_process_id);
    log::info!("Arch: {}", process_architecture);
    log::info!("Integrity: {}", process_integrity);
    log::info!("Elevated: {}", agent_is_elevated);
}