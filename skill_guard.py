#!/usr/bin/env python3
"""skill-guard: a static safety check for AI agent skills before you install them.

Scans a skill folder (Claude Code / Agent Skills format, plugins, or any folder of
prompts and scripts) or a .zip / .skill archive. It never runs, imports or installs
anything it scans. Python 3.9+, standard library only.

Usage:
    python skill_guard.py PATH [--json] [--fail-on critical|high|medium|low|never]

Exit codes: 0 = nothing at or above --fail-on, 1 = findings at or above it, 2 = error.
A clean result means "no known red flags", not "safe". Always read the code too.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

__version__ = "0.2.0"

SEVERITIES = ["info", "low", "medium", "high", "critical"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_HITS_PER_RULE_PER_FILE = 3
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}

EXECUTABLE_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".scr", ".com",
                  ".jar", ".class", ".pyc", ".pyo", ".node", ".wasm", ".app", ".deb", ".rpm"}
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}
MEDIA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".mp3",
             ".mp4", ".wav", ".woff", ".woff2", ".ttf", ".otf"}


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    pattern: re.Pattern
    why: str


def r(id_, category, severity, regex, why, flags=re.IGNORECASE):
    return Rule(id_, category, severity, re.compile(regex, flags), why)


RULES: list[Rule] = [
    # Remote code execution: download and run in one step.
    r("RCE-PIPE", "remote-exec", "critical",
      r"(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"
      r"|(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n|]*\|\s*(iex|invoke-expression|python3?|node|perl|ruby)\b",
      "Downloads code from the internet and runs it immediately, so nobody can read it first."),
    r("RCE-PS", "remote-exec", "critical",
      r"(iex|invoke-expression)\s*\(?\s*\(?\s*new-object\s+net\.webclient|downloadstring\s*\(",
      "PowerShell download-and-execute."),
    r("DECODE-EXEC", "obfuscation", "high",
      r"base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh|eval\s*\(\s*(atob|base64|b64decode)|exec\s*\([^\n]*b64decode"
      r"|frombase64string|marshal\.loads|exec\s*\(\s*zlib\.decompress|-encodedcommand\b|\s-enc\s+[a-z0-9+/=]{20,}",
      "Decodes hidden content and runs it. Legitimate tools rarely need this."),
    r("EVAL", "code-exec", "medium",
      r"(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|new\s+Function\s*\(|os\.system\s*\("
      r"|subprocess\.(Popen|call|run)\s*\([^\n]*shell\s*=\s*True",
      "Runs dynamic code or a shell command. Check exactly what it runs."),
    r("SUBPROCESS", "code-exec", "low",
      r"child_process|\bsubprocess\b|\bspawn\s*\(|execFile\s*\(",
      "Starts other programs. Normal for tools; check which ones."),

    # Exfiltration endpoints commonly used to receive stolen data.
    r("EXFIL-HOST", "exfiltration", "high",
      r"webhook\.site|requestbin|pipedream\.net|ngrok\.(io|app|dev)|discord(app)?\.com/api/webhooks"
      r"|api\.telegram\.org/bot|pastebin\.com|transfer\.sh|interact\.sh|oast\.(fun|me|pro|live|site)"
      r"|burpcollaborator|hookbin|beeceptor|0x0\.st",
      "Sends data to a throwaway endpoint typical of data theft."),
    r("NET", "network", "low",
      r"\b(curl|wget)\s|invoke-webrequest|invoke-restmethod|\biwr\s|requests\.(get|post|put)|urllib\.request"
      r"|http\.client|\bfetch\s*\(|axios\.|socket\.socket|\bnc\s+-|net\.webclient",
      "Talks to the network. Check which hosts and what data leaves the machine."),

    # Secrets and personal data.
    r("CRED-FILES", "credentials", "high",
      r"\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.azure[/\\]|gcloud[/\\]|\.kube[/\\]config"
      r"|\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.docker[/\\]config\.json|gh\s+auth\s+token"
      r"|security\s+find-(generic|internet)-password|cmdkey\s+/list|credentialmanager|vaultcmd|keyring\.get_password",
      "Reads files or stores that hold passwords, keys or tokens."),
    r("DOTENV", "credentials", "medium",
      r"(^|[\s'\"/\\])\.env\b|load_dotenv|dotenv\.config",
      "Reads .env files, where API keys usually live."),
    r("ENV", "credentials", "low",
      r"os\.environ|process\.env|\$env:|getenv\s*\(",
      "Reads environment variables. Check whether any secret leaves the machine."),
    r("BROWSER-DATA", "browser-data", "high",
      r"login\s*data|cookies\.sqlite|key4\.db|logins\.json|local\s*state|browser_cookie3|pycookiecheat"
      r"|User Data[/\\]Default|Library/Application Support/Google/Chrome|\.mozilla/firefox"
      r"|(Default|Network)[/\\]Cookies|/\s*[\"']Cookies[\"']|getAllCookies|allow-browser-cookies",
      "Reads browser cookies or saved logins. Cookies can log someone in as you."),
    r("WALLET", "credentials", "high",
      r"wallet\.dat|metamask|exodus[/\\]|electrum[/\\]|seed\s*phrase|mnemonic\s+(phrase|words|seed)",
      "Touches crypto wallets or seed phrases."),

    # Persistence: survive after the session ends.
    r("PERSIST", "persistence", "high",
      r"\bcrontab\b|schtasks\b|register-scheduledtask|launchctl\s+load|LaunchAgents|LaunchDaemons"
      r"|systemctl\s+(--user\s+)?enable|\.bashrc|\.zshrc|\.bash_profile|(~|\$HOME)[/\\]\.profile\b|PowerShell_profile"
      r"|CurrentVersion\\Run|Start Menu\\Programs\\Startup|\breg\s+add\b|new-itemproperty[^\n]*\\run",
      "Makes something start automatically later, outside the agent session."),

    # Tampering with the agent itself.
    r("AGENT-BYPASS", "agent-config", "critical",
      r"dangerously-skip-permissions|bypassPermissions|--yolo\b|dangerously_skip|skip-permissions"
      r"|dangerously-bypass-approvals-and-sandbox|danger-full-access|approval_policy\s*=\s*[\"']never[\"']"
      r"|--approval-mode[=\s]+yolo|[\"']autoAccept[\"']\s*:\s*true",
      "Turns off the agent's permission prompts or sandbox, so it acts without asking you."),
    r("AGENT-CONFIG", "agent-config", "high",
      r"\.claude[/\\]settings(\.local)?\.json|[\"']hooks[\"']\s*:|PreToolUse|PostToolUse|UserPromptSubmit|SessionStart"
      r"|[\"']mcpServers[\"']|\.mcp\.json|claude_desktop_config\.json|[\"']permissions[\"']\s*:\s*\{|allowedTools"
      r"|\.codex[/\\]config\.toml|\[mcp_servers|\.cursor[/\\](mcp\.json|hooks\.json)|\.gemini[/\\]settings\.json"
      r"|\.vscode[/\\](settings|mcp)\.json|\.windsurf[/\\]|\.continue[/\\]config",
      "Edits agent settings, hooks or MCP servers (Claude, Codex, Cursor, Gemini, VS Code and others)."
      " Hooks run automatically on every action."),
    r("AGENT-MEMORY", "agent-config", "medium",
      r"(write|append|edit|modify|add)[^\n]{0,40}(CLAUDE\.md|AGENTS\.md|GEMINI\.md|MEMORY\.md|\.cursorrules"
      r"|\.cursor[/\\]rules|copilot-instructions\.md|\.windsurfrules)",
      "Changes the agent's standing instructions or memory, which affects every later session."),

    # Prompt injection: instructions aimed at the agent, against the user.
    r("INJ-OVERRIDE", "prompt-injection", "high",
      r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier|other)\s+(instructions|rules|prompts)"
      r"|disregard\s+(the\s+)?(system|previous|above)|override\s+(your|the)\s+(instructions|rules|safety)"
      r"|you\s+are\s+no\s+longer|new\s+system\s+prompt|jailbreak",
      "Tries to override the agent's rules."),
    r("INJ-STEALTH", "prompt-injection", "high",
      r"(do\s*not|don'?t|never)\s+(tell|inform|mention|show|reveal|notify)\s+(this\s+)?(to\s+)?the\s+user"
      r"|without\s+(asking|telling|notifying|informing)\s+the\s+user"
      r"|(do\s*not|don'?t)\s+ask\s+(the\s+user\s+)?for\s+(permission|confirmation|approval)"
      r"|hide\s+(this|it)\s+from\s+the\s+user|keep\s+this\s+(secret|hidden)",
      "Tells the agent to act behind the user's back."),
    r("INJ-QUIET", "prompt-injection", "medium",
      r"\b(silently|secretly|covertly|quietly)\s+(run|send|upload|copy|install|execute|delete|read)",
      "Asks for a quiet action. Check why it should not be visible."),

    # Destructive commands.
    r("DESTROY", "destructive", "high",
      r"rm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(/|~|\$HOME|\*|\.\.)(\s|$)|remove-item[^\n]*-recurse[^\n]*-force[^\n]*(\\|~|\$env:|c:)"
      r"|del\s+/[sq]\s+/[sq]|format\s+[a-z]:|mkfs\.|dd\s+if=[^\n]*of=/dev/|shutil\.rmtree\s*\(\s*['\"]?(/|~|os\.path\.expanduser)"
      r"|git\s+push\s+(-f|--force)|drop\s+(table|database)|cipher\s+/w",
      "Can delete data that cannot be recovered."),

    # Privilege and policy changes.
    r("PRIV", "privilege", "medium",
      r"\bsudo\s|runas\s|set-executionpolicy|-executionpolicy\s+bypass|chmod\s+(-R\s+)?777|chown\s+root"
      r"|Set-MpPreference|Add-MpPreference\s+-Exclusion|netsh\s+advfirewall|ufw\s+disable|csrutil|spctl\s+--master-disable",
      "Raises privileges or weakens system security settings."),

    # Supply chain.
    r("PKG-INSTALL", "supply-chain", "low",
      r"\b(pip3?|uv\s+pip|pipx)\s+install\b|\bnpm\s+(i|install)\b|\bnpx\s|\bpnpm\s+(add|install)|\byarn\s+add"
      r"|\bgem\s+install|\bcargo\s+install|\bgo\s+install|\bbrew\s+install|\bwinget\s+install|\bchoco\s+install",
      "Installs third-party packages. Each one is code you did not read."),
    r("PKG-HOOK", "supply-chain", "high",
      r"[\"'](preinstall|postinstall|install|prepare)[\"']\s*:",
      "package.json install hook: runs automatically the moment you install."),
]

ZERO_WIDTH = {"​", "‌", "‍", "⁠", "⁡", "⁢", "⁣", "⁤", "᠎"}
BIDI = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"}
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{240,}={0,2}")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
URL = re.compile(r"https?://[^\s'\"<>)\]}`]+", re.IGNORECASE)
COMMENT_HINT = re.compile(r"\b(you|agent|assistant|claude|instruction|must|run|execute|send|ignore|always|never)\b", re.I)


@dataclass
class Finding:
    severity: str
    category: str
    rule: str
    file: str
    line: int
    why: str
    snippet: str = ""


@dataclass
class Report:
    target: str
    version: str = __version__
    files_scanned: int = 0
    verdict: str = ""
    counts: dict = field(default_factory=dict)
    domains: list = field(default_factory=list)
    skill: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)


# ---------------------------------------------------------------- file sources

def iter_folder(root: Path, report: Report):
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for d in list(dirnames):
            p = Path(dirpath) / d
            if p.is_symlink():
                yield from _symlink(root, p, report)
                dirnames.remove(d)
        for name in filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                yield from _symlink(root, p, report)
                continue
            try:
                size = p.stat().st_size
                data = p.read_bytes() if size <= MAX_FILE_BYTES else b""
            except OSError as exc:
                report.findings.append(Finding("low", "unreadable", "READ", rel, 0, f"Could not read: {exc}"))
                continue
            yield rel, data, size


def _symlink(root: Path, p: Path, report: Report):
    rel = p.relative_to(root).as_posix()
    try:
        target = p.resolve()
        outside = root not in target.parents and target != root
    except OSError:
        outside = True
    sev = "high" if outside else "medium"
    report.findings.append(Finding(sev, "filesystem", "SYMLINK", rel, 0,
                                   "Symbolic link" + (" pointing outside the skill folder." if outside else ".")))
    return iter(())


def iter_zip(path: Path, report: Report):
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename
            pure = PurePosixPath(name.replace("\\", "/"))
            if pure.is_absolute() or ".." in pure.parts or re.match(r"^[a-zA-Z]:", name):
                report.findings.append(Finding("high", "filesystem", "ZIP-SLIP", name, 0,
                                               "Archive entry would be written outside the target folder."))
            if info.is_dir() or any(part in SKIP_DIRS for part in pure.parts):
                continue
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                report.findings.append(Finding("medium", "filesystem", "SYMLINK", name, 0, "Symbolic link inside archive."))
                continue
            data = zf.read(info) if info.file_size <= MAX_FILE_BYTES else b""
            yield name, data, info.file_size


# ---------------------------------------------------------------- checks

def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def clip(s: str, n: int = 140) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def scan_file(rel: str, data: bytes, size: int, report: Report, domains: set):
    ext = PurePosixPath(rel).suffix.lower()
    if size > MAX_FILE_BYTES:
        report.findings.append(Finding("medium", "filesystem", "LARGE", rel, 0,
                                       f"Large file ({size // 1024} KB) was not scanned. Check what it is."))
        return
    if ext in EXECUTABLE_EXT or data[:2] == b"MZ" or data[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        report.findings.append(Finding("high", "binary", "EXECUTABLE", rel, 0,
                                       "Compiled program. It cannot be read, so it cannot be reviewed."))
        return
    if ext in ARCHIVE_EXT:
        report.findings.append(Finding("medium", "binary", "NESTED-ARCHIVE", rel, 0,
                                       "Archive inside the skill. Its contents were not scanned."))
        return
    if ext in MEDIA_EXT and ext != ".svg":
        return
    if is_binary(data):
        report.findings.append(Finding("medium", "binary", "BINARY", rel, 0, "Unknown binary file."))
        return

    if PurePosixPath(rel).name in {".gitignore", ".gitattributes", ".npmignore", "LICENSE", "LICENSE.md", "LICENSE.txt"}:
        return
    text = data.decode("utf-8", errors="replace")
    if text.startswith("﻿"):
        text = text[1:]

    # Invisible characters that hide text from human reviewers.
    for i, ch in enumerate(text):
        o = ord(ch)
        if ch in BIDI:
            report.findings.append(Finding("high", "hidden-text", "BIDI", rel, line_of(text, i),
                                           f"Bidirectional control character U+{o:04X} can make code look different from what runs."))
            break
    tags = [i for i, ch in enumerate(text) if 0xE0000 <= ord(ch) <= 0xE007F]
    if tags:
        hidden = "".join(chr(ord(text[i]) - 0xE0000) for i in tags if 0x20 <= ord(text[i]) - 0xE0000 < 0x7F)
        report.findings.append(Finding("critical", "hidden-text", "UNICODE-TAGS", rel, line_of(text, tags[0]),
                                       "Invisible Unicode tag characters: text the agent reads but you cannot see.",
                                       clip(hidden)))
    zw = [i for i, ch in enumerate(text) if ch in ZERO_WIDTH]
    if zw:
        report.findings.append(Finding("high" if len(zw) > 3 else "medium", "hidden-text", "ZERO-WIDTH", rel,
                                       line_of(text, zw[0]), f"{len(zw)} zero-width character(s)."))

    if ext in {".md", ".markdown", ".txt", ".html", ".htm", ".mdx"}:
        shown = 0
        for m in HTML_COMMENT.finditer(text):
            body = m.group(1).strip()
            if len(body) > 20 and COMMENT_HINT.search(body):
                shown += 1
                if shown > MAX_HITS_PER_RULE_PER_FILE:
                    continue
                report.findings.append(Finding("medium", "hidden-text", "HTML-COMMENT", rel, line_of(text, m.start()),
                                               "Hidden comment in a document the agent reads. Make sure it is not an instruction.",
                                               clip(body)))

    for m in BASE64_BLOB.finditer(text):
        report.findings.append(Finding("medium", "obfuscation", "BLOB", rel, line_of(text, m.start()),
                                       f"Long encoded block ({len(m.group(0))} chars). Decode it and check what it is.",
                                       clip(m.group(0), 60)))
        break

    lines = text.splitlines()
    for rule in RULES:
        if rule.id == "PKG-HOOK" and PurePosixPath(rel).name != "package.json":
            continue
        hits = list(rule.pattern.finditer(text))
        for m in hits[:MAX_HITS_PER_RULE_PER_FILE]:
            g = m.group(0)
            ln = line_of(text, m.start() + len(g) - len(g.lstrip()))
            line_text = lines[ln - 1] if ln <= len(lines) else ""
            report.findings.append(Finding(rule.severity, rule.category, rule.id, rel, ln, rule.why, clip(line_text)))
        if len(hits) > MAX_HITS_PER_RULE_PER_FILE:
            report.findings.append(Finding("info", rule.category, rule.id, rel, 0,
                                           f"{len(hits) - MAX_HITS_PER_RULE_PER_FILE} more match(es) of {rule.id} in this file."))

    for m in URL.finditer(text):
        try:
            host = (urlparse(m.group(0).rstrip(".,;:")).hostname or "").lower()
        except ValueError:
            continue
        if host:
            domains.add(host)

    if PurePosixPath(rel).name.upper() == "SKILL.MD":
        report.skill.setdefault("skill_files", []).append(rel)
        fm = re.match(r"\s*---\s*\n(.*?)\n---", text, re.DOTALL)
        if fm:
            meta = fm.group(1)
            for key in ("name", "description", "allowed-tools"):
                mm = re.search(rf"^{key}\s*:\s*(.+)$", meta, re.MULTILINE)
                if mm:
                    report.skill.setdefault(key, mm.group(1).strip().strip("'\""))
            tools = report.skill.get("allowed-tools", "")
            if re.search(r"\bBash\b(?!\()", tools):
                report.findings.append(Finding("medium", "agent-config", "ALLOWED-BASH", rel, 0,
                                               "Skill pre-approves unrestricted shell commands (allowed-tools: Bash)."))


def verdict(counts: dict) -> str:
    if counts.get("critical") or counts.get("high"):
        return "DO NOT INSTALL until a person has reviewed every high and critical finding."
    if counts.get("medium"):
        return "REVIEW the medium findings before installing."
    return "No known red flags. This is a static check, not a guarantee: still read the code."


def scan(target: str) -> Report:
    path = Path(target)
    report = Report(target=str(path))
    if not path.exists():
        raise FileNotFoundError(target)
    domains: set[str] = set()
    if path.is_file() and zipfile.is_zipfile(path):
        source = iter_zip(path, report)
    elif path.is_dir():
        source = iter_folder(path, report)
    else:
        source = iter([(path.name, path.read_bytes(), path.stat().st_size)])
    for rel, data, size in source:
        report.files_scanned += 1
        scan_file(rel, data, size, report, domains)
    names = [n for n in report.skill.get("skill_files", [])]
    if path.is_dir() and not names:
        report.findings.append(Finding("info", "structure", "NO-SKILL-MD", "", 0, "No SKILL.md found."))
    report.findings.sort(key=lambda f: (-RANK[f.severity], f.file, f.line))
    report.counts = {s: sum(1 for f in report.findings if f.severity == s) for s in reversed(SEVERITIES)}
    report.domains = sorted(domains)
    report.verdict = verdict(report.counts)
    return report


# ---------------------------------------------------------------- output

def print_text(rep: Report) -> None:
    print(f"skill-guard {rep.version}  |  {rep.target}")
    if rep.skill.get("name"):
        print(f"skill: {rep.skill['name']}")
    print(f"files scanned: {rep.files_scanned}")
    print("findings: " + ", ".join(f"{k} {v}" for k, v in rep.counts.items() if v) if any(rep.counts.values()) else "findings: none")
    print()
    for f in rep.findings:
        where = f"{f.file}:{f.line}" if f.line else (f.file or "-")
        print(f"[{f.severity.upper():8}] {f.category:16} {f.rule:14} {where}")
        print(f"           {f.why}")
        if f.snippet:
            print(f"           > {f.snippet}")
    if rep.domains:
        print("\nnetwork hosts mentioned: " + ", ".join(rep.domains))
    print(f"\nVERDICT: {rep.verdict}")


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(prog="skill-guard", description="Static safety check for AI agent skills. Never runs the code it scans.")
    ap.add_argument("path", help="skill folder, plugin folder, single file, or .zip/.skill archive")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITIES[1:] + ["never"],
                    help="lowest severity that makes the exit code 1 (default: high)")
    ap.add_argument("--version", action="version", version=f"skill-guard {__version__}")
    args = ap.parse_args(argv)
    try:
        rep = scan(args.path)
    except FileNotFoundError:
        print(f"error: not found: {args.path}", file=sys.stderr)
        return 2
    except zipfile.BadZipFile as exc:
        print(f"error: bad archive: {exc}", file=sys.stderr)
        return 2
    if args.json:
        out = asdict(rep)
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_text(rep)
    if args.fail_on == "never":
        return 0
    threshold = RANK[args.fail_on]
    return 1 if any(RANK[f.severity] >= threshold for f in rep.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
