#[path = "../tui_ctl.rs"]
mod tui_ctl;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tui_ctl::run_ctl_ui()
}
