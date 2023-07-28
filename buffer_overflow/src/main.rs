#![allow(unused_imports)]
use crate::{smep_kpti::exploit_with_kpti, smep_no_kpti::exploit_without_kpti};

mod smep_kpti;
mod smep_no_kpti;

fn main() {
    println!("Windows Kernel Exploitation - Buffer Overflow (Stack Overflow) by memN0ps");

    //exploit_without_kpti();
    exploit_with_kpti();
}
