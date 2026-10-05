//! A Model Context Protocol server: JSON-RPC 2.0 over stdio, no new crates.
//!
//! An agent calls android-doctor as tools instead of shelling out and parsing stdout, so
//! findings arrive as structured data. `handle` is a pure function so the protocol can be
//! tested without spawning a process.
use anyhow::Result;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::PathBuf;

/// The tools this server exposes, in MCP `tools/list` shape.
pub fn tool_list() -> Value {
    json!({ "tools": [
        tool("identify", "Identify the format of a firmware file",
              r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}"#),
        tool("doctor", "Report security and quality findings for a directory",
              r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}"#),
        tool("audit", "Security findings for a partition image",
              r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}"#),
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

/// Run one tool and return its output as text.
fn call_tool(name: &str, args: &Value) -> Result<String> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument \"path\""))?;
    let p = PathBuf::from(path);
    let out = match name {
        "identify" => {
            let id = crate::detect::identify_path(&p)?;
            format!("{}: {}", id.id, id.description)
        }
        "doctor" => {
            // Finding is not Serialize, so build the JSON explicitly - the same shape the
            // CLI already emits for --json.
            let findings = crate::doctor::scan(&p)?;
            let rows: Vec<Value> = findings
                .iter()
                .map(|f| {
                    json!({
                        "id": f.id,
                        "category": f.category,
                        "severity": f.severity,
                        "subject": f.subject,
                        "message": f.message,
                        "remedy": f.remedy,
                    })
                })
                .collect();
            serde_json::to_string_pretty(&rows)?
        }
        "audit" => {
            let audit = crate::audit::audit_image(&p)?;
            let rows: Vec<Value> = audit
                .findings
                .iter()
                .map(|f| {
                    json!({
                        "severity": format!("{:?}", f.severity),
                        "rule": f.rule,
                        "detail": f.detail,
                    })
                })
                .collect();
            serde_json::to_string_pretty(&rows)?
        }
        other => anyhow::bail!("unknown tool {other}"),
    };
    Ok(out)
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
