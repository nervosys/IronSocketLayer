//! The requirements traceability matrix is checked, not trusted.
//!
//! `docs/TRACEABILITY.md` must list every `REQ-*` tag the source carries and
//! nothing else, and every test it cites must exist. Delete a test, rename a
//! requirement, or add one without tracing it, and this fails.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(p);
        }
    }
}

fn tags_in(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let b = text.as_bytes();
    let mut i = 0;
    while let Some(at) = text[i..].find("REQ-") {
        let start = i + at;
        let mut end = start + 4;
        while end < b.len()
            && (b[end].is_ascii_uppercase() || b[end].is_ascii_digit() || b[end] == b'-')
        {
            end += 1;
        }
        let tag = text[start..end].trim_end_matches('-');
        // REQ-AREA-NNN only; skips prose like "REQ-*".
        if tag
            .rsplit('-')
            .next()
            .map(|n| n.len() == 3 && n.bytes().all(|c| c.is_ascii_digit()))
            .unwrap_or(false)
        {
            out.insert(tag.to_string());
        }
        i = end;
    }
    out
}

struct Row {
    id: String,
    method: String,
    evidence: String,
}

fn matrix() -> Vec<Row> {
    let doc = std::fs::read_to_string(crate_dir().join("../../docs/TRACEABILITY.md"))
        .expect("docs/TRACEABILITY.md");
    doc.lines()
        .filter(|l| l.starts_with("| REQ-"))
        .map(|l| {
            let cols: Vec<&str> = l.split('|').map(str::trim).collect();
            Row {
                id: cols[1].to_string(),
                method: cols[4].to_string(),
                evidence: cols[5].to_string(),
            }
        })
        .collect()
}

#[test]
fn every_requirement_in_the_source_is_traced_and_nothing_else() {
    let mut files = Vec::new();
    rust_files(&crate_dir().join("src"), &mut files);
    let mut in_source = BTreeSet::new();
    for f in &files {
        in_source.extend(tags_in(&std::fs::read_to_string(f).unwrap()));
    }
    let rows = matrix();
    let in_matrix: BTreeSet<String> = rows.iter().map(|r| r.id.clone()).collect();
    assert_eq!(
        rows.len(),
        in_matrix.len(),
        "a requirement appears twice in the matrix"
    );
    let untraced: Vec<_> = in_source.difference(&in_matrix).collect();
    let orphaned: Vec<_> = in_matrix.difference(&in_source).collect();
    assert!(
        untraced.is_empty(),
        "requirements in the source but not the matrix: {untraced:?}"
    );
    assert!(
        orphaned.is_empty(),
        "requirements in the matrix but not the source: {orphaned:?}"
    );
}

#[test]
fn every_cited_test_exists_and_every_requirement_is_verified() {
    for row in matrix() {
        match row.method.as_str() {
            "Test" => {
                let refs: Vec<&str> = row
                    .evidence
                    .split(';')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect();
                assert!(!refs.is_empty(), "{} has no verifying test", row.id);
                for r in refs {
                    let (file, func) = r
                        .rsplit_once("::")
                        .unwrap_or_else(|| panic!("{}: bad reference {r}", row.id));
                    let text = std::fs::read_to_string(crate_dir().join(file))
                        .unwrap_or_else(|_| panic!("{}: {file} does not exist", row.id));
                    let needle = format!("fn {func}(");
                    let at = text
                        .find(&needle)
                        .unwrap_or_else(|| panic!("{}: {file} has no {func}", row.id));
                    // The function must be a test: #[test] within the few lines above it.
                    let before = &text[at.saturating_sub(400)..at];
                    assert!(
                        before.contains("#[test]"),
                        "{}: {func} is not a #[test]",
                        row.id
                    );
                }
            }
            "Analysis" | "Review" => {
                assert!(
                    row.evidence.len() > 40,
                    "{}: an analysis must state its argument",
                    row.id
                );
            }
            other => panic!("{}: unknown verification method {other}", row.id),
        }
    }
}
