mod freeze;

fn main() {
    env_logger::init();
    log::info!("Freeze");
    freeze::freeze();
}