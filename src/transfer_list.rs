//! Parser for Android block-OTA `*.transfer.list` files (full OTAs: new/zero/erase).
use anyhow::{Context, Result, bail};

/// Half-open block ranges `[start, end)`.
pub type Ranges = Vec<(u64, u64)>;

#[derive(Debug, PartialEq)]
pub enum Command {
    New(Ranges),
    Zero(Ranges),
    Erase(Ranges),
}

#[derive(Debug, PartialEq)]
pub struct TransferList {
    pub version: u32,
    pub total_blocks: u64,
    pub commands: Vec<Command>,
}

/// Parse `N,a,b,c,d,...` into `[a,b)` pairs; N must equal the count of numbers that follow.
fn parse_ranges(s: &str) -> Result<Ranges> {
    let nums = s
        .split(',')
        .map(|n| {
            n.parse::<u64>()
                .with_context(|| format!("bad range number {n:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let (&count, rest) = nums.split_first().context("empty range set")?;
    if count as usize != rest.len() || rest.len() % 2 != 0 {
        bail!(
            "range set {s:?}: count {count} does not match {} numbers",
            rest.len()
        );
    }
    rest.chunks(2)
        .map(|p| {
            if p[0] < p[1] {
                Ok((p[0], p[1]))
            } else {
                bail!("empty or reversed range {}-{}", p[0], p[1])
            }
        })
        .collect()
}

pub fn parse(text: &str) -> Result<TransferList> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let version: u32 = lines
        .next()
        .context("missing version line")?
        .parse()
        .context("bad version")?;
    if !(1..=4).contains(&version) {
        bail!("unsupported transfer list version {version}");
    }
    let total_blocks = lines
        .next()
        .context("missing total blocks line")?
        .parse()
        .context("bad total blocks")?;
    if version >= 2 {
        for what in ["stash entries", "max stash"] {
            lines
                .next()
                .with_context(|| format!("missing {what} line"))?;
        }
    }
    let mut commands = Vec::new();
    for line in lines {
        let (name, args) = line
            .split_once(' ')
            .with_context(|| format!("malformed command {line:?}"))?;
        let ranges = || parse_ranges(args.trim()).with_context(|| format!("in {line:?}"));
        commands.push(match name {
            "new" => Command::New(ranges()?),
            "zero" => Command::Zero(ranges()?),
            "erase" => Command::Erase(ranges()?),
            other => bail!("unsupported command {other:?} (incremental OTAs are not supported)"),
        });
    }
    Ok(TransferList {
        version,
        total_blocks,
        commands,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v4_with_all_commands() {
        let t = parse("4\n10\n0\n0\nnew 2,0,4\nzero 4,4,6,8,10\nerase 2,6,8\n").unwrap();
        assert_eq!(t.version, 4);
        assert_eq!(t.total_blocks, 10);
        assert_eq!(
            t.commands,
            vec![
                Command::New(vec![(0, 4)]),
                Command::Zero(vec![(4, 6), (8, 10)]),
                Command::Erase(vec![(6, 8)]),
            ]
        );
    }

    #[test]
    fn v1_has_no_stash_lines() {
        let t = parse("1\n8\nnew 2,0,8\n").unwrap();
        assert_eq!(t.commands, vec![Command::New(vec![(0, 8)])]);
    }

    #[test]
    fn rejects_incremental_commands() {
        let e = parse("4\n10\n0\n0\nbsdiff 0 1 a b 2,0,1 1 2,0,1\n").unwrap_err();
        assert!(e.to_string().contains("unsupported command"), "{e}");
    }

    #[test]
    fn rejects_bad_ranges() {
        assert!(parse("4\n10\n0\n0\nnew 3,0,4\n").is_err(), "count mismatch");
        assert!(parse("4\n10\n0\n0\nnew 2,5,5\n").is_err(), "empty range");
        assert!(parse("4\n10\n0\n0\nnew 2,x,5\n").is_err(), "not a number");
    }

    #[test]
    fn rejects_bad_header() {
        assert!(parse("5\n10\n0\n0\n").is_err(), "unknown version");
        assert!(parse("4\n10\n").is_err(), "missing stash lines");
        assert!(parse("").is_err(), "empty input");
    }
}
