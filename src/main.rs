mod ekko;

fn main() {
    env_logger::init();
    log::info!("[*] Ekko Sleep Obfuscation by @memN0ps. Full credits to Paul (@C5pider), Austin Hudson (@SecIdiot), Peter Winter-Smith (@peterwintrsmith)");

    loop {
        // Start Sleep Obfuscation
        ekko::ekko();
    }
}
