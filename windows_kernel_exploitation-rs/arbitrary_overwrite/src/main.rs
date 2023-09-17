#![allow(unused_imports)]
use crate::{kcfg::exploit_with_kcfg, no_kcfg::exploit_without_kcfg};

mod kcfg;
mod no_kcfg;

fn main() {
    println!(
        "### Windows Kernel Exploitation - Arbitrary Overwrite (Write-What-Where) by memN0ps ###"
    );

    exploit_with_kcfg();
    //exploit_without_kcfg();
}
