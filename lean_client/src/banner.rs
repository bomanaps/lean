use std::io::IsTerminal;

const TEAL: &str = "\x1b[38;2;77;182;172m";
const DIM: &str = "\x1b[90m";
const RESET: &str = "\x1b[0m";

const WORDMARK: &str = "\
 ██╗     ███████╗  █████╗  ███╗   ██╗
 ██║     ██╔════╝ ██╔══██╗ ████╗  ██║
 ██║     █████╗   ███████║ ██╔██╗ ██║
 ██║     ██╔══╝   ██╔══██║ ██║╚██╗██║
 ███████╗███████╗ ██║  ██║ ██║ ╚████║
 ╚══════╝╚══════╝ ╚═╝  ╚═╝ ╚═╝  ╚═══╝";

pub fn banner() -> String {
    let (teal, dim, reset) = if std::io::stdout().is_terminal() {
        (TEAL, DIM, RESET)
    } else {
        ("", "", "")
    };

    format!(
        "\n{teal}{wordmark}{reset}\n\n           {dim}A lean consensus client{reset}\n           {dim}v{version} | {os} | {arch}{reset}\n",
        teal = teal,
        wordmark = WORDMARK,
        reset = reset,
        dim = dim,
        version = env!("CARGO_PKG_VERSION"),
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
    )
}
