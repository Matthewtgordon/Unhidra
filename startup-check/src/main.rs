use std::process::Command;

fn main() {
    println!("==================================================");
    println!("             UNHIDRA SERVICE STATUS");
    println!("==================================================");

    let ports = [
        ("Gateway", "9000"),
        ("Auth", "9100"),
        ("Chat", "9200"),
        ("Presence", "9300"),
        ("History", "9400"),
        ("Bot", "9500"),
    ];

    for (name, port) in &ports {
        let status = Command::new("bash")
            .arg("-c")
            .arg(format!("nc -z 127.0.0.1 {} >/dev/null 2>&1 && echo UP || echo DOWN", port))
            .output()
            .expect("failed to check port");
        let text = String::from_utf8_lossy(&status.stdout).trim().to_string();
        println!("{:<15}: {}", name, text);
    }

    println!("\nAuth API:       http://127.0.0.1:9100");
    println!("Gateway WS:     ws://127.0.0.1:9000/ws");
    println!("DB Path:        /opt/unhidra/auth.db");
    println!("==================================================");
}
