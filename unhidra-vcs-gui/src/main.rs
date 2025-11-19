use eframe::egui;
use std::process::Command;

const SCRIPT: &str = "/home/unhidra/unhidra-rust/unhidra-vcs.sh";

fn run(cmd: &[&str]) -> String {
    let out = Command::new(SCRIPT)
        .args(cmd)
        .output()
        .expect("Failed to run unhidra-vcs.sh");

    let mut s = String::new();
    if !out.stdout.is_empty() {
        s.push_str(&String::from_utf8_lossy(&out.stdout));
    }
    if !out.stderr.is_empty() {
        s.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    s
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_simple_native("Unhidra VCS", options, move |ctx, _frame| {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Unhidra VCS Controller");

            ui.separator();

            if ui.button("Save Snapshot").clicked() {
                let _ = run(&["save"]);
            }

            if ui.button("List Snapshots").clicked() {
                let out = run(&["list"]);
                ui.label(out);
            }

            ui.separator();

            static mut OLD: String = String::new();
            static mut NEW: String = String::new();

            unsafe {
                ui.horizontal(|ui| {
                    ui.label("Old:");
                    ui.text_edit_singleline(&mut OLD);
                });

                ui.horizontal(|ui| {
                    ui.label("New:");
                    ui.text_edit_singleline(&mut NEW);
                });

                if ui.button("Diff").clicked() {
                    if !OLD.is_empty() && !NEW.is_empty() {
                        let out = run(&["diff", &OLD, &NEW]);
                        ui.label(out);
                    }
                }

                if ui.button("Checkout").clicked() {
                    if !NEW.is_empty() {
                        let _ = run(&["checkout", &NEW]);
                    }
                }
            }
        });
    })
}
