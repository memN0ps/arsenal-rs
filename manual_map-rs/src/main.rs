use sysinfo::{Pid, SystemExt, ProcessExt};
mod lib;

fn main() {
    let dll_bytes = include_bytes!("C:\\Users\\User\\Documents\\GitHub\\arsenal-rs\\example\\target\\debug\\example.dll");
    let process_id = get_process_id_by_name("notepad.exe") as u32;
    println!("Process ID: {:}", process_id);

    lib::manual_map(dll_bytes, process_id);
}

// Get Process ID
fn get_process_id_by_name(target_process: &str) -> Pid {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    let mut process_id = 0;

    for process in system.process_by_name(target_process) {
        process_id = process.pid();
    }

    return process_id;
}