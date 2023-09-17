#![allow(unused_imports)]
use crate::{
    pool_overflow_arbitrary_read_write::exploit_pool_overflow_arbitrary_read_write,
    smep_kpti::exploit_with_kpti, smep_no_kpti::exploit_without_kpti,
};

mod pool_overflow_arbitrary_read_write;
mod smep_kpti;
mod smep_no_kpti;

fn main() {
    println!("Windows Kernel Exploitation - Buffer Overflow (Stack Overflow) by memN0ps");

    //exploit_without_kpti();
    exploit_with_kpti();
    exploit_pool_overflow_arbitrary_read_write();
}
