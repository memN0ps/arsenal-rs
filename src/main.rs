mod ekko;

fn main() {
    env_logger::init();
    log::info!("[*] Ekko Sleep Obfuscation by @memN0ps and @trickster0. Full credits to Paul (@C5pider), Austin Hudson (@SecIdiot), Peter Winter-Smith (@peterwintrsmith)");

    let mut secret_key = "1234567890ABCDEF\0".as_bytes().to_vec();
    ekko::ekko(4000, &mut secret_key);
}
