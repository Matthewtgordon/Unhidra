use chrono::Local;
use eframe::egui;
use std::fs;

const SNAP_DIR: &str = "/home/unhidra/unhidra-backups";

struct SnapshotApp {
    snapshots: Vec<String>,
    selected_a: Option<String>,
    selected_b: Option<String>,
    diff_output: String,
}

impl SnapshotApp {
    fn new() -> Self {
        fs::create_dir_all(SNAP_DIR).unwrap();

        let mut app = Self {
            snapshots: Vec::new(),
            selected_a: None,
            selected_b: None,
            diff_output: String::new(),
        };
        app.load_snapshots();
        app
    }

    fn load_snapshots(&mut self) {
        self.snapshots.clear();

        if let Ok(entries) = fs::read_dir(SNAP_DIR) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("snap-") {
                    self.snapshots.push(name);
                }
            }
        }

        self.snapshots.sort();
    }

    fn save_snapshot(&mut self) {
        let ts = Local::now().timestamp();
        let file = format!("{}/snap-{}", SNAP_DIR, ts);
        let _ = fs::write(&file, b"snapshot placeholder");
        self.load_snapshots();
    }

    fn diff_snapshots(&mut self) {
        match (&self.selected_a, &self.selected_b) {
            (Some(a), Some(b)) => {
                self.diff_output = format!(
                    "Diff between:\n{}\n{}\n(diff not implemented yet)",
                    a,
                    b
                );
            }
            _ => {
                self.diff_output = "Select TWO snapshots to diff.".to_string();
            }
        }
    }
}

impl eframe::App for SnapshotApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel::left("snap_list").show(ctx, |ui| {
            ui.heading("Snapshots");

            if ui.button("Save Snapshot").clicked() {
                self.save_snapshot();
            }

            ui.separator();
            ui.label("Select A:");
            for snap in &self.snapshots {
                if ui.button(snap).clicked() {
                    self.selected_a = Some(snap.clone());
                }
            }

            ui.separator();
            ui.label("Select B:");
            for snap in &self.snapshots {
                if ui.button(snap).clicked() {
                    self.selected_b = Some(snap.clone());
                }
            }

            ui.separator();
            if ui.button("Diff").clicked() {
                self.diff_snapshots();
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Diff Result");
            ui.separator();
            ui.label(&self.diff_output);
        });
    }
}

fn main() -> eframe::Result<()> {
    let app = SnapshotApp::new();
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Unhidra Snapshot Manager",
        options,
        Box::new(|_| Box::new(app)),
    )
}
