use minify_js::{minify, Session, TopLevelMode};
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};
use walkdir::WalkDir;

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let templates = Path::new(&manifest).join("src/templates");
    let output = Path::new(&manifest).join("static");

    if !templates.exists() {
        return;
    }

    // Track changes for JS and CSS
    println!("cargo:rerun-if-changed={}", templates.display());
    for entry in WalkDir::new(&templates).into_iter().filter_map(|e| e.ok()) {
        let ext = entry.path().extension().and_then(|e| e.to_str());
        if matches!(ext, Some("js") | Some("css")) {
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }

    let _ = fs::create_dir_all(&output);

    build_js(&templates, &output);
    build_css(&templates, &output);
}

fn build_js(templates: &Path, output: &Path) {
    let mut files: Vec<_> = WalkDir::new(templates)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|e| e == "js"))
        .map(|e| e.path().to_path_buf())
        .collect();
    files.sort();

    if files.is_empty() {
        return;
    }

    let mut combined = String::new();
    for file in &files {
        if let Ok(content) = fs::read_to_string(file) {
            let rel = file.strip_prefix(templates).unwrap_or(file);
            combined.push_str(&format!("\n// === {} ===\n", rel.display()));
            combined.push_str(&content);
            combined.push('\n');
        }
    }

    if combined.is_empty() {
        return;
    }

    let minified = try_minify_js(&combined).unwrap_or_else(|| combined.clone());
    let hash = hex::encode(Sha256::digest(minified.as_bytes()));
    let short = &hash[..8];

    let _ = fs::write(output.join(format!("app.{}.min.js", short)), &minified);
    let _ = fs::write(output.join("app.min.js"), &minified);

    if env::var("PROFILE").map_or(true, |p| p != "release") {
        let _ = fs::write(output.join("app.debug.js"), &combined);
    }

    println!("cargo:warning=Built app.min.js ({} bytes)", minified.len());
}

fn build_css(templates: &Path, output: &Path) {
    let mut combined = String::new();

    // Base styles first
    let base = output.join("styles.css");
    if base.exists() {
        if let Ok(content) = fs::read_to_string(&base) {
            combined.push_str(&content);
            combined.push('\n');
        }
    }

    // Then template CSS
    let mut files: Vec<_> = WalkDir::new(templates)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|e| e == "css"))
        .map(|e| e.path().to_path_buf())
        .collect();
    files.sort();

    for file in files {
        if let Ok(content) = fs::read_to_string(&file) {
            if content.trim().is_empty() {
                continue;
            }
            let rel = file.strip_prefix(templates).unwrap_or(&file);
            combined.push_str(&format!("\n/* === {} === */\n", rel.display()));
            combined.push_str(&content);
            combined.push('\n');
        }
    }

    if combined.trim().is_empty() {
        return;
    }

    let minified = minify_css(&combined);
    let hash = hex::encode(Sha256::digest(minified.as_bytes()));
    let short = &hash[..8];

    let _ = fs::write(output.join(format!("styles.{}.min.css", short)), &minified);
    let _ = fs::write(output.join("styles.min.css"), &minified);

    println!(
        "cargo:warning=Built styles.min.css ({} bytes)",
        minified.len()
    );
}

fn try_minify_js(source: &str) -> Option<String> {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let src = source.to_string();
    catch_unwind(AssertUnwindSafe(|| {
        let session = Session::new();
        let mut out = Vec::new();
        minify(&session, TopLevelMode::Module, src.as_bytes(), &mut out).ok()?;
        String::from_utf8(out).ok()
    }))
    .ok()?
}

fn minify_css(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut in_comment = false;
    let mut chars = css.chars().peekable();

    while let Some(c) = chars.next() {
        if in_comment {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_comment = false;
            }
            continue;
        }
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_comment = true;
            continue;
        }
        if c.is_whitespace() {
            if !out.ends_with(|ch: char| ch.is_whitespace() || "{:;,".contains(ch))
                && chars.peek().is_some_and(|&n| !"{}:;,".contains(n))
            {
                out.push(' ');
            }
            continue;
        }
        out.push(c);
    }
    out
}
