use std::{io};
use sysinfo::{Pid, SystemExt, ProcessExt};
use clap::Parser;

/* 
/// Manual Mapping Library
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Target process to inject PE
    #[clap(short, long)]
    process: String,

    /// Path to the dll to inject
    #[clap(short, long)]
    dll: String,
}*/

mod lib;

fn main() {
    let dll_bytes = include_bytes!("C:\\Tools\\ReflectiveDLLInjection-master\\x64\\Release\\reflective_dll.x64.dll");
    let process_id = get_process_id_by_name("notepad.exe") as u32;
    //let args = Args::parse();

    //let dll_path = args.dll;
    //let process_id = get_process_id_by_name(args.process.as_str());
    println!("Process ID: {:}", process_id);

    lib::manual_map(dll_bytes, process_id);
}

#[allow(dead_code)]
// Gets user input from the terminal
fn get_input() -> io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

#[allow(dead_code)]
// Used for debugging
fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
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