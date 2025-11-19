use std::fs;
use std::io::{stdout, Write};
use std::path::Path;
use crossterm::{
    cursor,
    event::{read, Event, KeyCode},
    execute,
    terminal::{self, ClearType},
};

/// Reads all snapshots in ~/unhidra-backups
pub fn tui_main() {
    let base = "/home/unhidra/unhidra-backups";

    let mut snapshots: Vec<String> = fs::read_dir(base)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path().display().to_string())
        .collect();

    snapshots.sort();

    let mut index: i32 = snapshots.len() as i32 - 1;

    terminal::enable_raw_mode().unwrap();
    execute!(stdout(), terminal::EnterAlternateScreen).unwrap();

    loop {
        draw(&snapshots, index as usize);

        match read().unwrap() {
            Event::Key(k) => match k.code {
                KeyCode::Up => {
                    if index > 0 {
                        index -= 1;
                    }
                }
                KeyCode::Down => {
                    if index < snapshots.len() as i32 - 1 {
                        index += 1;
                    }
                }
                KeyCode::Char('q') => {
                    break;
                }
                _ => {}
            },
            _ => {}
        }
    }

    execute!(stdout(), terminal::LeaveAlternateScreen).unwrap();
    terminal::disable_raw_mode().unwrap();
}

/// Render the TUI screen
fn draw(list: &Vec<String>, index: usize) {
    execute!(
        stdout(),
        terminal::Clear(ClearType::All),
        cursor::MoveTo(0, 0)
    )
    .unwrap();

    println!("UNHIDRA SNAPSHOT VIEWER (q to quit)");
    println!("=================================\n");

    for (i, item) in list.iter().enumerate() {
        if i == index {
            println!("> {}", item);
        } else {
            println!("  {}", item);
        }
    }

    println!("\n---------------------------------\n");

    if list.len() >= 2 {
        // Show diff against previous snapshot
        if index > 0 {
            let a = &list[index - 1];
            let b = &list[index];

            println!("Diff between:\n{}\nAND\n{}\n", a, b);

            let diff = crate::simple_diff::diff_paths(Path::new(a), Path::new(b));
            println!("{}", diff);
        } else {
            println!("Select a later snapshot to see diff.");
        }
    } else {
        println!("Not enough snapshots for diff.");
    }
}
