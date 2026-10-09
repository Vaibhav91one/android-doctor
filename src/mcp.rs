//! A Model Context Protocol server: JSON-RPC 2.0 over stdio, no new crates.
//!
//! An agent calls android-doctor as tools instead of shelling out and parsing stdout, so
//! findings arrive as structured data. `handle` is a pure function so the protocol can be
//! tested without spawning a process.
use anyhow::Result;
use serde_json::{Value, json};
use std::io::{BufRead, Write};

/// Flags the findings tools accept besides the target path(s). Excluded over MCP: `--json`
/// (always on), `--score`, `--no-color` (never any colour in JSON), `help` and `version`.
const FLAGS: &str = r#""baseline":{"type":"string","description":"Previous --json envelope; marks findings new/unchanged and exits 3 on a new one"},"fail_on":{"type":"string","enum":["critical","high","medium","low","info"],"description":"Exit 1 (3 under baseline) at or above this severity"},"sarif":{"type":"string","description":"Also write SARIF 2.1.0 to this file""#;

/// The tools this server exposes, in MCP `tools/list` shape.
pub fn tool_list() -> Value {
    let one = r#""path":{"type":"string"}"#;
    let many = r#""paths":{"type":"array","items":{"type":"string"},"description":"Image files or directories"}"#;
    let schema = |p: &str, req: &str, flags: bool| {
        let f = if flags {
            format!(",{FLAGS}}}")
        } else {
            String::new()
        };
        format!(r#"{{"type":"object","properties":{{{p}{f}}},"required":[{req}]}}"#)
    };
    json!({ "tools": [
        tool("identify", "Identify the format of a firmware file (identify --json)",
              &schema(one, r#""path""#, false)),
        tool("doctor", "doctor scan --json: the doctor/1 envelope for a firmware directory",
              &schema(one, r#""path""#, true)),
        tool("audit", "audit --json: the doctor/1 envelope for partition images",
              &schema(&format!("{one},{many}"), "", true)),
        tool("diff", "diff --json: the doctor/1 envelope comparing two firmware builds file by file; findings are what the new build made worse",
              &schema(r#""old":{"type":"string","description":"Old image or directory of images"},"new":{"type":"string","description":"New image or directory of images"},"only":{"type":"array","items":{"type":"string","enum":["added","removed","modified","metadata"]},"description":"List only these file changes under data"}"#, r#""old","new""#, true)),
    ] })
}

fn tool(name: &str, description: &str, schema: &str) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": serde_json::from_str::<Value>(schema).expect("static schema parses"),
    })
}

/// Handle one JSON-RPC request and return the response, or `None` for a notification.
pub fn handle(req: &Value) -> Option<Value> {
    let method = req.get("method").and_then(Value::as_str)?;
    // JSON-RPC: a request without an id is a notification and must NEVER be answered, not
    // even with an error. Check that before anything else.
    let id = req.get("id").cloned()?;

    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "android-doctor", "version": env!("CARGO_PKG_VERSION") },
        }),
        "tools/list" => tool_list(),
        "tools/call" => {
            let name = req
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = req
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or(json!({}));
            match call_tool(name, &args) {
                Ok(text) => json!({
                    "content": [{ "type": "text", "text": text }],
                    "isError": false,
                }),
                Err(e) => json!({
                    "content": [{ "type": "text", "text": format!("{e:#}") }],
                    "isError": true,
                }),
            }
        }
        // Unknown methods get a proper error rather than silence.
        other => return Some(error(Some(id), -32601, &format!("unknown method {other}"))),
    };

    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn error(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// The CLI arguments for a tool call (everything after the binary name).
fn cli_args(name: &str, args: &Value) -> Result<Vec<String>> {
    let text = |k: &str| args.get(k).and_then(Value::as_str);
    let mut argv: Vec<String> = match name {
        "identify" => vec!["identify".into()],
        "doctor" => vec!["doctor".into(), "scan".into()],
        "audit" => vec!["audit".into()],
        "diff" => vec!["diff".into()],
        other => anyhow::bail!("unknown tool {other}"),
    };
    argv.push("--json".into());
    for (key, flag) in [
        ("baseline", "baseline"),
        ("fail_on", "fail-on"),
        ("sarif", "sarif"),
    ] {
        if let Some(v) = text(key) {
            if name == "identify" {
                anyhow::bail!("identify takes only \"path\"");
            }
            argv.push(format!("--{flag}={v}"));
        }
    }
    if name == "diff" {
        let (Some(old), Some(new)) = (text("old"), text("new")) else {
            anyhow::bail!("missing required arguments \"old\" and \"new\"");
        };
        if let Some(a) = args.get("only").and_then(Value::as_array) {
            let v: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
            argv.push(format!("--only={}", v.join(",")));
        }
        argv.extend(["--".into(), old.into(), new.into()]);
        return Ok(argv);
    }
    let mut paths: Vec<String> = text("path").map(String::from).into_iter().collect();
    if let Some(a) = args.get("paths").and_then(Value::as_array) {
        paths.extend(a.iter().filter_map(Value::as_str).map(String::from));
    }
    if paths.is_empty() || (name != "audit" && paths.len() > 1) {
        anyhow::bail!("missing required argument \"path\"");
    }
    argv.push("--".into());
    argv.extend(paths);
    Ok(argv)
}

/// Run one tool: the CLI itself with `--json`, so the reply is byte-identical to the CLI's
/// stdout. Exit 0, 1 and 3 are results (the envelope says which); anything else is an error.
fn call_tool(name: &str, args: &Value) -> Result<String> {
    let out = std::process::Command::new(std::env::current_exe()?)
        .arg("--no-color")
        .args(cli_args(name, args)?)
        .output()?;
    if matches!(out.status.code(), Some(0 | 1 | 3)) {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    anyhow::bail!(
        "{} (exit {})",
        String::from_utf8_lossy(&out.stderr).trim(),
        out.status.code().map_or("signal".into(), |c| c.to_string())
    )
}

/// Serve JSON-RPC over stdin/stdout until EOF.
pub fn serve(verbose: bool) -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if verbose {
            eprintln!("<- {line}");
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                // Malformed input must produce an error response, not a crash: an agent
                // will happily send us garbage.
                let resp = error(None, -32700, &format!("parse error: {e}"));
                writeln!(stdout, "{resp}")?;
                stdout.flush()?;
                continue;
            }
        };
        if let Some(resp) = handle(&req) {
            if verbose {
                eprintln!("-> {resp}");
            }
            writeln!(stdout, "{resp}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, id: Option<i64>) -> Value {
        match id {
            Some(i) => json!({ "jsonrpc": "2.0", "id": i, "method": method, "params": {} }),
            None => json!({ "jsonrpc": "2.0", "method": method, "params": {} }),
        }
    }

    #[test]
    fn initialize_advertises_tool_capability() {
        let r = handle(&req("initialize", Some(1))).unwrap();
        assert_eq!(r["id"], 1);
        assert_eq!(r["jsonrpc"], "2.0");
        assert!(r["result"]["capabilities"]["tools"].is_object());
        assert_eq!(r["result"]["serverInfo"]["name"], "android-doctor");
    }

    #[test]
    fn tools_list_returns_parseable_schemas() {
        let r = handle(&req("tools/list", Some(2))).unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        for t in tools {
            assert!(t["name"].is_string());
            assert!(t["description"].is_string());
            assert!(t["inputSchema"]["type"] == "object");
        }
    }

    #[test]
    fn a_notification_gets_no_response() {
        // No id means notification: answering would be wrong.
        assert!(handle(&req("notifications/initialized", None)).is_none());
    }

    #[test]
    fn an_unknown_method_is_an_error_not_silence() {
        let r = handle(&req("does/not/exist", Some(3))).unwrap();
        assert_eq!(r["error"]["code"], -32601);
        assert!(r["result"].is_null());
    }

    #[test]
    fn calling_a_tool_without_its_argument_reports_an_error_not_a_crash() {
        let call = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "identify", "arguments": {} }
        });
        let r = handle(&call).unwrap();
        assert_eq!(r["result"]["isError"], true);
        assert!(
            r["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("path")
        );
    }

    #[test]
    fn an_unknown_tool_is_an_error_result() {
        let call = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": { "name": "nope", "arguments": { "path": "/tmp" } }
        });
        let r = handle(&call).unwrap();
        assert_eq!(r["result"]["isError"], true);
    }

    #[test]
    fn a_request_with_no_method_is_ignored_rather_than_panicking() {
        assert!(handle(&json!({ "jsonrpc": "2.0", "id": 6 })).is_none());
    }
}
