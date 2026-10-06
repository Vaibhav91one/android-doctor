//! Exploit-mitigation triage of native ELF objects (`.so` and executables), checksec style.
//!
//! Clean-room read of the public ELF format: the file is only parsed, never run or loaded. Every
//! offset is bounds-checked; a truncated or hostile file gives an error, never a panic.
//!
//! Heuristics, said plainly: the stack-canary and FORTIFY checks look at the names in the dynamic
//! string table (`__stack_chk_fail`, `__*_chk`) rather than walking the symbol table, so a
//! statically linked binary (no dynamic section) is not judged for them.

use crate::audit::{Finding, Severity};
use crate::tree::{Entry, Kind};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// Largest object we read, most objects per image and most bytes of them (a hostile image can
/// hold millions of files).
pub const MAX_ELF_BYTES: u64 = 64 << 20;
const MAX_ELF_COUNT: usize = 20_000;
const MAX_ELF_TOTAL_BYTES: u64 = 512 << 20;
/// Paths named in one aggregated finding.
const DETAIL_PATHS: usize = 3;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;
const DT_NULL: u64 = 0;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_BIND_NOW: u64 = 24;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Relro {
    None,
    Partial,
    Full,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ElfInfo {
    pub bits: u8,
    pub big_endian: bool,
    /// An executable (`ET_EXEC`, or has a `PT_INTERP`), as opposed to a shared object.
    pub executable: bool,
    /// `ET_EXEC`: linked at a fixed address.
    pub no_pie: bool,
    pub exec_stack: bool,
    pub relro: Relro,
    /// `None` when there is no dynamic section to judge from.
    pub canary: Option<bool>,
    pub fortify: Option<bool>,
}

struct Rd<'a> {
    d: &'a [u8],
    be: bool,
    is64: bool,
}

impl Rd<'_> {
    fn bytes<const N: usize>(&self, off: u64) -> Result<[u8; N]> {
        usize::try_from(off)
            .ok()
            .and_then(|o| self.d.get(o..o.checked_add(N)?))
            .and_then(|s| s.try_into().ok())
            .with_context(|| {
                format!("read of {N} bytes at offset {off} is past the end of the file")
            })
    }
    fn u16(&self, off: u64) -> Result<u16> {
        let b = self.bytes(off)?;
        Ok(if self.be {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    }
    fn u32(&self, off: u64) -> Result<u32> {
        let b = self.bytes(off)?;
        Ok(if self.be {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }
    fn u64(&self, off: u64) -> Result<u64> {
        let b = self.bytes(off)?;
        Ok(if self.be {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    }
    /// A word the width of the class (`Elf32_Addr` / `Elf64_Addr` and friends).
    fn word(&self, off: u64) -> Result<u64> {
        if self.is64 {
            self.u64(off)
        } else {
            self.u32(off).map(u64::from)
        }
    }
}

struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

/// Parse one object. `Ok(None)` for an ELF that is neither an executable nor a shared object
/// (relocatable, core): there is nothing to judge.
pub fn parse(d: &[u8]) -> Result<Option<ElfInfo>> {
    if d.get(..4) != Some(b"\x7fELF") {
        bail!("not an ELF file");
    }
    let is64 = match d.get(4).copied() {
        Some(1) => false,
        Some(2) => true,
        c => bail!("unknown ELF class {c:?}"),
    };
    let be = match d.get(5).copied() {
        Some(1) => false,
        Some(2) => true,
        e => bail!("unknown ELF byte order {e:?}"),
    };
    let r = Rd { d, be, is64 };
    let etype = r.u16(16).context("reading e_type")?;
    if etype != 2 && etype != 3 {
        return Ok(None);
    }
    let (phoff, phentsize, phnum) = if is64 {
        (r.u64(32)?, r.u16(54)?, r.u16(56)?)
    } else {
        (u64::from(r.u32(28)?), r.u16(42)?, r.u16(44)?)
    };
    let min = if is64 { 56 } else { 32 };
    if phnum > 0 && phentsize < min {
        bail!(
            "program header entry size {phentsize} is smaller than the {min} bytes the format needs"
        );
    }
    let mut ph = Vec::new();
    for i in 0..u64::from(phnum) {
        let o = phoff
            .checked_add(i * u64::from(phentsize))
            .with_context(|| format!("program header {i} offset overflows"))?;
        let h = if is64 {
            Phdr {
                kind: r.u32(o)?,
                flags: r.u32(o + 4)?,
                offset: r.u64(o + 8)?,
                vaddr: r.u64(o + 16)?,
                filesz: r.u64(o + 32)?,
            }
        } else {
            Phdr {
                kind: r.u32(o)?,
                flags: r.u32(o + 24)?,
                offset: u64::from(r.u32(o + 4)?),
                vaddr: u64::from(r.u32(o + 8)?),
                filesz: u64::from(r.u32(o + 16)?),
            }
        };
        ph.push(h);
    }
    let executable = etype == 2 || ph.iter().any(|h| h.kind == PT_INTERP);
    // No PT_GNU_STACK means the loader's default, an executable stack, on an executable.
    let exec_stack = match ph.iter().find(|h| h.kind == PT_GNU_STACK) {
        Some(h) => h.flags & PF_X != 0,
        None => executable,
    };
    let mut info = ElfInfo {
        bits: if is64 { 64 } else { 32 },
        big_endian: be,
        executable,
        no_pie: etype == 2,
        exec_stack,
        relro: if ph.iter().any(|h| h.kind == PT_GNU_RELRO) {
            Relro::Partial
        } else {
            Relro::None
        },
        canary: None,
        fortify: None,
    };
    if let Some(dynh) = ph.iter().find(|h| h.kind == PT_DYNAMIC) {
        dynamic(&r, &ph, dynh, &mut info).context("reading the dynamic section")?;
    }
    Ok(Some(info))
}

fn dynamic(r: &Rd, ph: &[Phdr], dynh: &Phdr, info: &mut ElfInfo) -> Result<()> {
    let esz: u64 = if r.is64 { 16 } else { 8 };
    let (mut now, mut strtab, mut strsz) = (false, None, 0u64);
    for i in 0..dynh.filesz / esz {
        let o = dynh
            .offset
            .checked_add(i * esz)
            .context("dynamic entry offset overflows")?;
        let (tag, val) = (r.word(o)?, r.word(o + esz / 2)?);
        match tag {
            DT_NULL => break,
            DT_BIND_NOW => now = true,
            DT_FLAGS if val & DF_BIND_NOW != 0 => now = true,
            DT_FLAGS_1 if val & DF_1_NOW != 0 => now = true,
            DT_STRTAB => strtab = Some(val),
            DT_STRSZ => strsz = val,
            _ => {}
        }
    }
    if now && info.relro == Relro::Partial {
        info.relro = Relro::Full;
    }
    let Some(va) = strtab else { return Ok(()) };
    // DT_STRTAB is a virtual address: map it through the PT_LOAD segment that holds it.
    let off = ph
        .iter()
        .filter(|h| h.kind == PT_LOAD)
        .find_map(|h| {
            va.checked_sub(h.vaddr)
                .filter(|d| *d < h.filesz)
                .and_then(|d| h.offset.checked_add(d))
        })
        .context("DT_STRTAB is not inside any loadable segment")?;
    let start = usize::try_from(off).ok().filter(|o| *o <= r.d.len());
    let start = start.context("dynamic string table starts past the end of the file")?;
    let len = usize::try_from(strsz)
        .unwrap_or(usize::MAX)
        .min(r.d.len() - start);
    let names: Vec<&[u8]> = r.d[start..start + len].split(|b| *b == 0).collect();
    info.canary = Some(names.contains(&&b"__stack_chk_fail"[..]));
    info.fortify = Some(names.iter().any(|n| {
        n.len() > 6 && n.starts_with(b"__") && n.ends_with(b"_chk") && *n != b"__stack_chk_fail"
    }));
    Ok(())
}

/// Rules an object trips: severity, rule id, why.
pub fn issues(i: &ElfInfo) -> Vec<(Severity, &'static str, &'static str)> {
    let mut v = Vec::new();
    if i.no_pie {
        v.push((
            Severity::High,
            "elf-no-pie",
            "ET_EXEC: linked at a fixed address, so no ASLR",
        ));
    }
    if i.exec_stack {
        v.push((
            Severity::Medium,
            "elf-exec-stack",
            "executable stack (PT_GNU_STACK with X, or missing on an executable)",
        ));
    }
    match i.relro {
        Relro::None => v.push((
            Severity::Medium,
            "elf-no-relro",
            "no PT_GNU_RELRO: the GOT stays writable",
        )),
        Relro::Partial if i.canary.is_some() => v.push((
            Severity::Warn,
            "elf-partial-relro",
            "RELRO without BIND_NOW: lazy binding keeps the GOT writable",
        )),
        _ => {}
    }
    if i.canary == Some(false) {
        v.push((
            Severity::Warn,
            "elf-no-canary",
            "no __stack_chk_fail import (heuristic, from the dynamic string table)",
        ));
    }
    if i.fortify == Some(false) {
        v.push((
            Severity::Info,
            "elf-no-fortify",
            "no *_chk imports (heuristic, from the dynamic string table)",
        ));
    }
    v
}

#[derive(Debug, Clone, Default)]
pub struct ElfAudit {
    /// ELF objects judged.
    pub scanned: usize,
    /// Objects with at least one issue.
    pub objects: Vec<(String, ElfInfo)>,
    /// Objects whose ELF structure could not be read: path and why.
    pub errors: Vec<(String, String)>,
    /// A cap (count or bytes) stopped the scan early.
    pub truncated: bool,
}

/// Cheap filter before reading a file: a shared object by name, or anything executable.
fn candidate(e: &Entry) -> bool {
    e.kind == Kind::File
        && (52..=MAX_ELF_BYTES).contains(&e.size)
        && (e.path.contains(".so") || e.mode & 0o111 != 0)
}

pub fn scan_tree(entries: &[Entry], read: &mut dyn FnMut(&str) -> Result<Vec<u8>>) -> ElfAudit {
    let (mut a, mut tried, mut bytes) = (ElfAudit::default(), 0usize, 0u64);
    for e in entries.iter().filter(|e| candidate(e)) {
        if tried >= MAX_ELF_COUNT || bytes + e.size > MAX_ELF_TOTAL_BYTES {
            a.truncated = true;
            break;
        }
        tried += 1;
        let Ok(d) = read(&e.path) else { continue };
        bytes += d.len() as u64;
        if !d.starts_with(b"\x7fELF") {
            continue;
        }
        match parse(&d) {
            Ok(Some(info)) => {
                a.scanned += 1;
                if !issues(&info).is_empty() {
                    a.objects.push((e.path.clone(), info));
                }
            }
            Ok(None) => {}
            Err(err) => a.errors.push((e.path.clone(), format!("{err:#}"))),
        }
    }
    a
}

/// One finding per rule, naming a few objects. The key lists every path, so a newly affected
/// object changes the fingerprint and a baseline reports it as new.
pub fn findings(a: &ElfAudit) -> Vec<(Finding, (String, String))> {
    let mut rules: Vec<(Severity, &'static str, &'static str)> = Vec::new();
    for (_, i) in &a.objects {
        for x in issues(i) {
            if !rules.iter().any(|r| r.1 == x.1) {
                rules.push(x);
            }
        }
    }
    rules.sort_by_key(|r| r.0);
    rules
        .into_iter()
        .map(|(severity, rule, why)| {
            let paths: Vec<&str> = a
                .objects
                .iter()
                .filter(|(_, i)| issues(i).iter().any(|x| x.1 == rule))
                .map(|(p, _)| p.as_str())
                .collect();
            let shown = paths.len().min(DETAIL_PATHS);
            let mut detail = format!(
                "{} of {} ELF objects: {why}: {}",
                paths.len(),
                a.scanned,
                paths[..shown].join(", ")
            );
            if paths.len() > shown {
                detail.push_str(&format!(" (+{} more, see --json)", paths.len() - shown));
            }
            (
                Finding {
                    severity,
                    rule,
                    detail,
                },
                (String::new(), paths.join("\n")),
            )
        })
        .collect()
}

pub fn to_json(a: &ElfAudit) -> Value {
    json!({
        "scanned": a.scanned,
        "truncated": a.truncated,
        "objects": a.objects.iter().map(|(p, i)| json!({
            "path": p, "bits": i.bits, "big_endian": i.big_endian, "executable": i.executable,
            "no_pie": i.no_pie, "exec_stack": i.exec_stack,
            "relro": match i.relro { Relro::None => "none", Relro::Partial => "partial", Relro::Full => "full" },
            "stack_canary": i.canary, "fortify": i.fortify,
            "issues": issues(i).iter().map(|x| x.1).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "errors": a.errors.iter().map(|(p, e)| json!({"path": p, "error": e})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What to put in a hand-built ELF.
    #[derive(Clone)]
    struct Spec {
        is64: bool,
        be: bool,
        etype: u16,
        stack: Option<u32>, // PT_GNU_STACK flags
        relro: bool,
        now: Option<(u64, u64)>, // dynamic tag and value that give BIND_NOW
        strings: Vec<&'static str>,
        dynamic: bool,
    }

    fn base() -> Spec {
        Spec {
            is64: true,
            be: false,
            etype: 3,
            stack: Some(6),
            relro: true,
            now: Some((DT_FLAGS, DF_BIND_NOW)),
            strings: vec!["__stack_chk_fail", "__memcpy_chk"],
            dynamic: true,
        }
    }
    fn unhardened() -> Spec {
        Spec {
            etype: 2,
            stack: Some(7),
            relro: false,
            now: None,
            strings: vec!["memcpy"],
            ..base()
        }
    }

    fn put(v: &mut Vec<u8>, be: bool, size: usize, x: u64) {
        let mut s = x.to_le_bytes()[..size].to_vec();
        if be {
            s.reverse();
        }
        v.extend(s);
    }

    /// Layout: header, program headers, then at 0x200 the dynamic section and at 0x300 the string
    /// table. One PT_LOAD maps the first 0x400 bytes at vaddr 0x1000.
    fn build(s: &Spec) -> Vec<u8> {
        let (w, esz, phsz, ehsz) = if s.is64 {
            (8, 16, 56, 64)
        } else {
            (4, 8, 32, 52)
        };
        let mut strtab = vec![0u8];
        for n in &s.strings {
            strtab.extend(n.as_bytes());
            strtab.push(0);
        }
        let (dyn_off, str_off) = (0x200u64, 0x300u64);
        let mut tags = vec![
            (DT_STRTAB, 0x1000 + str_off),
            (DT_STRSZ, strtab.len() as u64),
        ];
        tags.extend(s.now);
        tags.push((DT_NULL, 0));
        let dyn_len = tags.len() as u64 * esz;
        // type, flags, offset, vaddr, filesz
        let mut phs: Vec<(u32, u32, u64, u64, u64)> = vec![(PT_LOAD, 5, 0, 0x1000, 0x400)];
        if s.dynamic {
            phs.push((PT_DYNAMIC, 6, dyn_off, 0x1000 + dyn_off, dyn_len));
        }
        if let Some(f) = s.stack {
            phs.push((PT_GNU_STACK, f, 0, 0, 0));
        }
        if s.relro {
            phs.push((PT_GNU_RELRO, 4, 0, 0, 0));
        }
        let mut v = vec![
            0x7f,
            b'E',
            b'L',
            b'F',
            if s.is64 { 2 } else { 1 },
            if s.be { 2 } else { 1 },
            1,
        ];
        v.resize(16, 0);
        put(&mut v, s.be, 2, u64::from(s.etype));
        put(&mut v, s.be, 2, 183);
        put(&mut v, s.be, 4, 1);
        put(&mut v, s.be, w, 0); // entry
        put(&mut v, s.be, w, ehsz as u64); // phoff
        put(&mut v, s.be, w, 0); // shoff
        put(&mut v, s.be, 4, 0);
        put(&mut v, s.be, 2, ehsz as u64);
        put(&mut v, s.be, 2, phsz as u64);
        put(&mut v, s.be, 2, phs.len() as u64);
        for _ in 0..3 {
            put(&mut v, s.be, 2, 0); // shentsize, shnum, shstrndx
        }
        assert_eq!(v.len(), ehsz);
        for (t, f, off, va, fsz) in phs {
            put(&mut v, s.be, 4, u64::from(t));
            if s.is64 {
                put(&mut v, s.be, 4, u64::from(f));
                for x in [off, va, va, fsz, fsz, 8] {
                    put(&mut v, s.be, 8, x);
                }
            } else {
                for x in [off, va, va, fsz, fsz] {
                    put(&mut v, s.be, 4, x);
                }
                put(&mut v, s.be, 4, u64::from(f));
                put(&mut v, s.be, 4, 4);
            }
        }
        v.resize(dyn_off as usize, 0);
        for (t, x) in tags {
            put(&mut v, s.be, w, t);
            put(&mut v, s.be, w, x);
        }
        v.resize(str_off as usize, 0);
        v.extend(strtab);
        v.resize(0x400, 0);
        v
    }

    fn rules_of(s: &Spec) -> Vec<&'static str> {
        let i = parse(&build(s)).unwrap().unwrap();
        issues(&i).iter().map(|x| x.1).collect()
    }

    fn ent(path: &str, size: u64, mode: u32) -> Entry {
        Entry {
            path: path.into(),
            kind: Kind::File,
            mode,
            uid: 0,
            gid: 0,
            size,
            mtime: 0,
            ino: 0,
            nlink: 1,
            link: None,
            rdev: None,
            xattrs: vec![],
            sha256: None,
            extracted_as: None,
        }
    }

    #[test]
    fn the_unhardened_executable_trips_every_rule() {
        let i = parse(&build(&unhardened())).unwrap().unwrap();
        assert!(i.executable && i.no_pie && i.exec_stack);
        assert_eq!(i.relro, Relro::None);
        assert_eq!((i.canary, i.fortify), (Some(false), Some(false)));
        assert_eq!(
            rules_of(&unhardened()),
            [
                "elf-no-pie",
                "elf-exec-stack",
                "elf-no-relro",
                "elf-no-canary",
                "elf-no-fortify"
            ]
        );
    }

    #[test]
    fn the_hardened_object_trips_none() {
        let i = parse(&build(&base())).unwrap().unwrap();
        assert_eq!(i.relro, Relro::Full);
        assert_eq!((i.canary, i.fortify), (Some(true), Some(true)));
        assert!(rules_of(&base()).is_empty());
    }

    #[test]
    fn each_rule_fires_alone() {
        let none: Vec<&str> = vec![];
        assert_eq!(rules_of(&Spec { etype: 2, ..base() }), ["elf-no-pie"]);
        assert_eq!(
            rules_of(&Spec {
                stack: Some(7),
                ..base()
            }),
            ["elf-exec-stack"]
        );
        assert_eq!(
            rules_of(&Spec {
                relro: false,
                now: None,
                ..base()
            }),
            ["elf-no-relro"]
        );
        assert_eq!(
            rules_of(&Spec {
                now: None,
                ..base()
            }),
            ["elf-partial-relro"]
        );
        assert_eq!(
            rules_of(&Spec {
                now: Some((DT_FLAGS_1, DF_1_NOW)),
                ..base()
            }),
            none
        );
        assert_eq!(
            rules_of(&Spec {
                now: Some((DT_BIND_NOW, 0)),
                ..base()
            }),
            none
        );
        assert_eq!(
            rules_of(&Spec {
                strings: vec!["__memcpy_chk"],
                ..base()
            }),
            ["elf-no-canary"]
        );
        assert_eq!(
            rules_of(&Spec {
                strings: vec!["__stack_chk_fail"],
                ..base()
            }),
            ["elf-no-fortify"]
        );
    }

    #[test]
    fn a_missing_gnu_stack_is_exec_stack_on_an_executable_only() {
        assert_eq!(
            rules_of(&Spec {
                etype: 2,
                stack: None,
                ..base()
            }),
            ["elf-no-pie", "elf-exec-stack"]
        );
        assert!(
            rules_of(&Spec {
                stack: None,
                ..base()
            })
            .is_empty()
        );
    }

    #[test]
    fn thirty_two_bit_and_big_endian_are_read() {
        for (is64, be) in [(false, false), (false, true), (true, true)] {
            let bad = Spec {
                is64,
                be,
                ..unhardened()
            };
            let i = parse(&build(&bad)).unwrap().unwrap();
            assert_eq!((i.bits, i.big_endian), (if is64 { 64 } else { 32 }, be));
            assert_eq!(rules_of(&bad).len(), 5, "{is64} {be}");
            assert!(
                rules_of(&Spec { is64, be, ..base() }).is_empty(),
                "{is64} {be}"
            );
        }
    }

    #[test]
    fn no_dynamic_section_is_not_judged_for_canary_or_fortify() {
        let s = Spec {
            dynamic: false,
            relro: false,
            now: None,
            ..base()
        };
        assert_eq!(rules_of(&s), ["elf-no-relro"]);
    }

    #[test]
    fn non_executables_are_skipped_and_non_elf_is_refused() {
        let mut rel = build(&base());
        rel[16] = 1; // ET_REL
        assert_eq!(parse(&rel).unwrap(), None);
        assert!(parse(b"MZ\x90\0").is_err());
        let mut bad_class = build(&base());
        bad_class[4] = 9;
        assert!(parse(&bad_class).unwrap_err().to_string().contains("class"));
    }

    #[test]
    fn hostile_and_truncated_files_never_panic() {
        let good = build(&unhardened());
        for n in 0..good.len() {
            let _ = parse(&good[..n]); // an error is fine, a panic is not
        }
        assert!(parse(&good[..40]).is_err());
        for i in 0..good.len() {
            for b in [0u8, 0xff] {
                let mut x = good.clone();
                x[i] = b;
                let _ = parse(&x);
            }
        }
        let mut x = good.clone();
        x[32..40].copy_from_slice(&u64::MAX.to_le_bytes()); // e_phoff
        assert!(parse(&x).is_err());
        let mut x = good;
        x[56..58].copy_from_slice(&u16::MAX.to_le_bytes()); // e_phnum
        assert!(parse(&x).is_err());
    }

    #[test]
    fn the_tree_scan_reads_only_candidates_and_aggregates_findings() {
        let (bad, good) = (build(&unhardened()), build(&base()));
        let entries = vec![
            ent("system/bin/bad", bad.len() as u64, 0o755),
            ent("system/lib64/good.so", good.len() as u64, 0o644),
            ent("system/etc/readme.txt", 100, 0o644),
            ent("system/bin/script", 60, 0o755),
        ];
        let mut read = |p: &str| -> Result<Vec<u8>> {
            Ok(match p {
                "system/bin/bad" => bad.clone(),
                "system/lib64/good.so" => good.clone(),
                "system/bin/script" => vec![b'#'; 60],
                _ => panic!("read {p}"),
            })
        };
        let a = scan_tree(&entries, &mut read);
        assert_eq!((a.scanned, a.objects.len(), a.errors.len()), (2, 1, 0));
        let f = findings(&a);
        assert_eq!(f.len(), 5);
        assert_eq!(f[0].0.rule, "elf-no-pie");
        assert!(
            f[0].0.detail.contains("1 of 2 ELF objects")
                && f[0].0.detail.contains("system/bin/bad")
        );
        assert_eq!(to_json(&a)["objects"][0]["relro"], "none");
    }

    #[test]
    fn a_broken_elf_in_the_tree_is_reported_not_fatal() {
        let mut d = build(&base());
        d.truncate(70);
        let entries = vec![ent("lib/x.so", 70, 0o644)];
        let a = scan_tree(&entries, &mut |_| Ok(d.clone()));
        assert_eq!(a.errors.len(), 1);
        assert!(a.errors[0].1.contains("past the end"), "{:?}", a.errors);
    }
}
