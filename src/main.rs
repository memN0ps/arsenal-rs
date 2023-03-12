mod ekko;

fn main() {
    env_logger::init();
    log::info!("[*] Ekko Sleep Obfuscation by @memN0ps and @trickster0. Full credits to Paul (@C5pider), Austin Hudson (@SecIdiot), Peter Winter-Smith (@peterwintrsmith)");
    ekko::ekko(2000);
}
