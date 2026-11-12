use super::ParserDiagnostics;
use super::cursor::Segment;
use super::read;
use super::read::Text;
use crate::diagnostic::Severity;
use crate::inbound::{InboundConfig, Socks5Inbound, Socks5User};

pub(super) fn parse_section(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<InboundConfig, super::ParseFailure> {
    let mut socks5 = Vec::new();
    for root in section {
        let Some(body) = root.body() else {
            continue;
        };
        for child in body {
            match read::block_header(&child) {
                Some(header) if header.raw() == "socks5" => {
                    socks5.push(parse_socks5(&child, diagnostics));
                }
                Some(header) => header.notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-block",
                    "unknown inbound block ignored; expected socks5",
                ),
                None => Text::segment(&child).notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-statement",
                    "unknown inbound statement ignored; expected a socks5 block",
                ),
            }
        }
    }
    Ok(InboundConfig { socks5 })
}

fn parse_socks5(block: &Segment<'_, '_>, diagnostics: &mut ParserDiagnostics<'_>) -> Socks5Inbound {
    let mut bind = String::new();
    let mut users: Vec<Socks5User> = Vec::new();
    let Some(body) = block.body() else {
        return Socks5Inbound { bind, users };
    };
    for child in body {
        if let Some(header) = read::block_header(&child) {
            if header.raw() == "users" {
                let Some(users_body) = child.body() else {
                    continue;
                };
                for line in users_body {
                    let line = Text::segment(&line);
                    let Some((key, value)) = line.kv() else {
                        line.notice(
                            diagnostics,
                            Severity::Warning,
                            "unknown-statement",
                            "unknown users entry ignored; expected username: password",
                        );
                        continue;
                    };
                    users.push(Socks5User {
                        username: key.unquote().raw().to_owned(),
                        password: value.unquote().raw().to_owned(),
                    });
                }
                continue;
            }
            header.notice(
                diagnostics,
                Severity::Warning,
                "unknown-block",
                "unknown socks5 block ignored; expected users",
            );
            continue;
        }
        let line = Text::segment(&child);
        let Some((key, value)) = line.kv() else {
            line.notice(
                diagnostics,
                Severity::Warning,
                "unknown-statement",
                "unknown socks5 statement ignored; expected bind or a users block",
            );
            continue;
        };
        if key.raw() != "bind" {
            key.notice(
                diagnostics,
                Severity::Warning,
                "unknown-key",
                "unknown socks5 key ignored; expected bind",
            );
            continue;
        }
        diagnostics.register_field("bind", value);
        bind = value.unquote().raw().to_owned();
    }
    Socks5Inbound { bind, users }
}
