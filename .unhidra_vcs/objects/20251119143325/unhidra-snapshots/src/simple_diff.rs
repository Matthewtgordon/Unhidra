use std::fs;

/// Extremely simple line-by-line diff.
/// This is NOT fancy but works well for flipbook-style inspection.
pub fn diff_paths(a: &std::path::Path, b: &std::path::Path) -> String {
    let a = fs::read_to_string(a).unwrap_or_default();
    let b = fs::read_to_string(b).unwrap_or_default();

    let mut out = String::new();

    let a_lines: Vec<_> = a.lines().collect();
    let b_lines: Vec<_> = b.lines().collect();

    let max = a_lines.len().max(b_lines.len());

    for i in 0..max {
        let left = a_lines.get(i).unwrap_or(&"");
        let right = b_lines.get(i).unwrap_or(&"");

        if left != right {
            out.push_str(&format!(" - {}\n + {}\n", left, right));
        }
    }

    if out.is_empty() {
        out = "No differences.\n".into();
    }

    out
}
