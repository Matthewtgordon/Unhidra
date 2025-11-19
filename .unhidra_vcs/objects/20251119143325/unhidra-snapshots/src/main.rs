use std::fs;
use std::fs::File;
use std::io::{Read};
use std::path::Path;
use tar::Archive;
use tar::Builder;

const SNAP_DIR: &str = "/home/unhidra/unhidra-backups";

fn save_snapshot() {
    fs::create_dir_all(SNAP_DIR).unwrap();
    let ts = chrono::Local::now().format("snap-%Y%m%d-%H%M%S.tar").to_string();
    let out = format!("{}/{}", SNAP_DIR, ts);
    let file = File::create(&out).unwrap();
    let mut tar = Builder::new(file);

    fn add_dir(tar: &mut Builder<File>, base: &Path, path: &Path) {
        let rel = match path.strip_prefix(base) {
            Ok(r) => r,
            Err(_) => return,
        };

        // exclusions
        if rel.components().any(|c| c.as_os_str() == ".git") {
            return;
        }
        if rel.to_string_lossy().contains("/target/") {
            return;
        }

        // file
        if path.is_file() {
            if let Ok(mut f) = File::open(path) {
                if tar.append_file(rel, &mut f).is_err() {
                    return;
                }
            }
            return;
        }

        // directory
        if path.is_dir() {
            let entries = fs::read_dir(path);
            if entries.is_err() {
                return;
            }
            for entry in entries.unwrap() {
                if let Ok(e) = entry {
                    add_dir(tar, base, &e.path());
                }
            }
        }
    }

    let root = Path::new("/home/unhidra/unhidra-rust");
    add_dir(&mut tar, root, root);
    tar.finish().unwrap();

    println!("Snapshot created: {}", out);
}

fn extract_to(path: &str, dir: &str) {
    let file = File::open(path).unwrap();
    let mut archive = Archive::new(file);
    archive.unpack(dir).unwrap();
}

fn diff_snapshots(a: &str, b: &str) {
    let old = "/tmp/snap_old";
    let new = "/tmp/snap_new";

    fs::remove_dir_all(old).ok();
    fs::remove_dir_all(new).ok();
    fs::create_dir_all(old).unwrap();
    fs::create_dir_all(new).unwrap();

    extract_to(a, old);
    extract_to(b, new);

    let output = std::process::Command::new("diff")
        .args(["-ruN", old, new])
        .output()
        .expect("failed to run diff");

    println!("{}", String::from_utf8_lossy(&output.stdout));
}

fn list_snapshots() {
    let mut snaps: Vec<_> = fs::read_dir(SNAP_DIR)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|f| f.ends_with(".tar"))
        .collect();

    snaps.sort();
    for s in snaps {
        println!("{}", s);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage: save | list | diff <A> <B>");
        return;
    }

    match args[1].as_str() {
        "save" => save_snapshot(),
        "list" => list_snapshots(),
        "diff" => {
            if args.len() != 4 {
                println!("diff requires: <snapshot1.tar> <snapshot2.tar>");
            } else {
                diff_snapshots(&args[2], &args[3]);
            }
        }
        _ => println!("Unknown command"),
    }
}
