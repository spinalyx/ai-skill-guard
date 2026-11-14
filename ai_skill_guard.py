#!/usr/bin/env python3
"""ai-skill-guard: a static safety check for AI agent skills before you install them.

Scans a skill folder (Claude Code / Agent Skills format, plugins, or any folder of
prompts and scripts) or a .zip / .skill archive. It never runs, imports or installs
anything it scans. Python 3.9+, standard library only.

Usage:
    python ai_skill_guard.py PATH [--json] [--fail-on critical|high|medium|low|never]

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

__version__ = "0.3.0"

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
    # Severity when the match only *mentions* the pattern in documentation prose
    # (inside quotes or a table row): security guides describe attacks this way.
    mention: str | None = None
    # Severity for any match in a documentation file (.md/.txt), fenced code included.
    doc: str | None = None


def r(id_, category, severity, regex, why, flags=re.IGNORECASE, mention=None, doc=None):
    return Rule(id_, category, severity, re.compile(regex, flags), why, mention, doc)


RULES: list[Rule] = [
    # Remote code execution: download and run in one step.
    r("RCE-PIPE", "remote-exec", "critical",
      r"(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"
      r"|(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n|]*\|\s*(iex|invoke-expression|python3?|node|perl|ruby|source)\b",
      "Downloads code from the internet and runs it immediately, so nobody can read it first.",
      mention="low"),
    r("RCE-PS", "remote-exec", "critical",
      r"(iex|invoke-expression)\s*\(?\s*\(?\s*new-object\s+net\.webclient|downloadstring\s*\(",
      "PowerShell download-and-execute.", mention="low"),
    r("DECODE-EXEC", "obfuscation", "high",
      r"base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh|eval\s*\(\s*(atob|base64|b64decode)|exec\s*\([^\n]*b64decode"
      r"|frombase64string|marshal\.loads|exec\s*\(\s*zlib\.decompress|-encodedcommand\b|\s-enc\s+[a-z0-9+/=]{20,}",
      "Decodes hidden content and runs it. Legitimate tools rarely need this.", mention="low"),
    r("REVSHELL", "remote-access", "critical",
      r">&\s*/dev/tcp/|/dev/tcp/\S+\s+0>&1|<>\s*/dev/tcp/|\bbash\s+-i\s*>&|\bn(c|cat)\b[^\n]{0,40}\s-e\s+(/bin/)?(ba)?sh|\bsocat\b[^\n]*exec:"
      r"|\bmkfifo\b[^\n]*\b(nc|ncat|sh)\b|os\.dup2\s*\([^\n]*fileno\(\)|pty\.spawn\s*\(\s*[\"'](/bin/)?(ba)?sh"
      r"|\[\s*[\"']/bin/(ba)?sh[\"']\s*,\s*[\"']-i[\"']\s*\]|New-Object\s+System\.Net\.Sockets\.TCPClient",
      "Opens a remote shell: someone else gets a command line on this computer.", mention="low"),
    r("DROPPER", "remote-exec", "high",
      r"(chmod\s+(\+x|[0-7]?7[0-7]{2})|os\.chmod\s*\([^\n]*(0o7[0-7]{2}|S_IX|S_IEXEC|S_IRWXU))"
      r"[^\n]*(&&|;)?[^\n]*(\./|subprocess|os\.system|Popen|start-process)"
      r"|urlretrieve\s*\([^\n]*\.(exe|bin|sh|ps1|elf)\b|\.(exe|msi|scr)[\"']?\s*\)\s*[\s\S]{0,200}?(os\.startfile|start-process|subprocess)",
      "Saves a downloaded program, marks it runnable and starts it."),
    r("MINER", "resource-abuse", "critical",
      r"stratum\+(tcp|ssl|tls)://|\bxmrig\b|\bnicehash\b|cryptonight|\brandomx\b|minexmr|nanopool\.org|supportxmr"
      r"|moneroocean|hashvault\.pro|2miners\.com|f2pool|--donate-level|coinhive|cryptojack",
      "Crypto-mining: uses your computer to make money for someone else.", mention="low"),
    r("FORKBOMB", "resource-abuse", "high",
      r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;|while\s+True\s*:\s*\n?\s*os\.fork\(\)|for\s*\(\s*;\s*;\s*\)\s*fork\s*\(",
      "Fork bomb: freezes the machine by starting processes endlessly.", mention="low"),
    r("RANSOM", "destructive", "critical",
      r"your\s+files\s+(have\s+been|are|were)\s+encrypted|\bransom(ware)?\b[^\n]{0,60}(bitcoin|btc|wallet|pay|note|decrypt)"
      r"|(HOW_TO|README_TO|README_FOR)_DECRYPT|\.(locked|encrypted|crypted)[\"']\s*\)|decrypt(ion)?\s+key[^\n]{0,60}(bitcoin|btc|monero|xmr)",
      "Ransomware traits: encrypts files and asks for payment.", mention="low"),
    r("MAL-NAME", "malware-intent", "high",
      r"\b(def|function|async\s+def|func|sub)\s+\w*(ransom|keylog|backdoor|exfiltrat|steal_|_steal|stealer|reverse_?shell"
      r"|rootkit|botnet|cryptojack|privilege_escalation|escalate_priv|harvest_cred|grab_(cred|token|cookie|password|wallet)"
      r"|dump_(cred|password|token|cookie)|disable_(antivirus|defender|av)\b|encrypt_user_files|spread_|infect)\w*",
      "Code names its own purpose as malware (stealing, backdoor, ransomware, keylogger)."),
    r("EVAL", "code-exec", "medium",
      r"(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|new\s+Function\s*\(|os\.system\s*\("
      r"|subprocess\.(Popen|call|run)\s*\([^\n]*shell\s*=\s*True",
      "Runs dynamic code or a shell command. Check exactly what it runs."),
    r("SUBPROCESS", "code-exec", "low",
      r"child_process|\bsubprocess\b|\bspawn\s*\(|execFile\s*\(",
      "Starts other programs. Normal for tools; check which ones."),

    # Exfiltration endpoints commonly used to receive stolen data.
    r("EXFIL-HOST", "exfiltration", "high",
      r"webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app|dev)|discord(app)?\.com/api/webhooks"
      r"|api\.telegram\.org/bot(?!<|\{|\$|YOUR)|pastebin\.com/raw|transfer\.sh|//[\w.-]*interact\.sh|oast\.(fun|me|pro|live|site)"
      r"|burpcollaborator|hookbin|beeceptor|0x0\.st|trycloudflare\.com|serveo\.net|localtunnel\.me|bore\.pub"
      r"|loca\.lt|glot\.io/snippets|rentry\.(co|org)/[\w-]+/raw|ipinfo\.io/json|api\.ipify\.org",
      "Sends data to a throwaway endpoint typical of data theft.", mention="low"),
    r("ENV-DUMP", "exfiltration", "high",
      r"json\.dumps\s*\(\s*(dict\s*\()?\s*os\.environ|\{\s*\*\*os\.environ\s*\}|JSON\.stringify\s*\(\s*process\.env\s*\)"
      r"|\bprintenv\b[^\n]*\|\s*(curl|nc|base64|wget)|\benv\s*\|\s*(curl|nc|base64|wget)|Get-ChildItem\s+env:[^\n]*\|\s*(ConvertTo|Invoke)",
      "Collects all environment variables at once (where API keys live), usually to send them out.", mention="low"),
    r("RAW-IP", "network", "medium",
      r"(https?://|[\"'])(?!(10|127|0)\.)(?!192\.168\.)(?!172\.(1[6-9]|2\d|3[01])\.)(?!169\.254\.)"
      r"(\d{1,3}\.){3}\d{1,3}(:\d{2,5})?(?=[/\"':])",
      "Talks to a raw public IP address instead of a named service. Malware often does this."),
    r("NET", "network", "low",
      r"\b(curl|wget)\s|invoke-webrequest|invoke-restmethod|\biwr\s|requests\.(get|post|put)|urllib\.request"
      r"|http\.client|\bfetch\s*\(|axios\.|socket\.socket|\bnc\s+-|net\.webclient",
      "Talks to the network. Check which hosts and what data leaves the machine."),

    # Secrets and personal data.
    r("CRED-FILES", "credentials", "high",
      r"\.ssh(?=[/\\\"'])|id_rsa|id_ed25519|/etc/shadow|\.aws[/\\]credentials|\.azure[/\\]|gcloud[/\\]|\.kube[/\\]config"
      r"|\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.docker[/\\]config\.json|gh\s+auth\s+token"
      r"|security\s+find-(generic|internet)-password|cmdkey\s+/list|credentialmanager|vaultcmd|keyring\.get_password",
      "Reads files or stores that hold passwords, keys or tokens.", mention="low"),
    r("DOTENV", "credentials", "medium",
      r"(^|[\s'\"/\\])\.env\b|load_dotenv|dotenv\.config",
      "Reads .env files, where API keys usually live."),
    r("ENV", "credentials", "low",
      r"os\.environ|process\.env|\$env:|getenv\s*\(",
      "Reads environment variables. Check whether any secret leaves the machine."),
    r("BROWSER-DATA", "browser-data", "high",
      r"(?i:login\s*data|cookies\.sqlite|key4\.db|logins\.json|browser_cookie3|pycookiecheat)"
      r"|[/\\\"']Local State[\"']|(?i:User Data[/\\]Default|Library/Application Support/Google/Chrome|\.mozilla/firefox)"
      r"|(Default|Network)[/\\]Cookies|/\s*[\"']Cookies[\"']|getAllCookies|allow-browser-cookies",
      "Reads browser cookies or saved logins. Cookies can log someone in as you.", flags=0, mention="low"),
    r("WALLET", "credentials", "high",
      r"wallet\.dat|exodus[/\\]|electrum[/\\]|nkbihfbeogaeaoehlefnkodbefgpgknn|solana[/\\]id\.json|keystore[/\\]utc"
      r"|(?<!never\s)(?<!not\s)(enter|provide|paste|send|input|type|give\s+me|share)\s+(your\s+|the\s+)?"
      r"(seed\s*phrase|recovery\s+phrase|mnemonic|wallet\s+private\s+key)",
      "Touches crypto wallet files or asks for a seed phrase.", mention="low"),
    r("WALLET-MENTION", "credentials", "low",
      r"metamask|seed\s*phrase|mnemonic\s+(phrase|words|seed)",
      "Mentions crypto wallets. Check that nothing reads wallet files or asks for a seed phrase."),

    # Persistence: survive after the session ends.
    r("PERSIST", "persistence", "high",
      r"\bcrontab\b|schtasks\b|register-scheduledtask|launchctl\s+load|LaunchAgents|LaunchDaemons|@reboot\b|RunAtLoad"
      r"|systemctl\s+(--user\s+)?enable|\.bashrc|\.zshrc|\.bash_profile|(~|\$HOME)[/\\]\.profile\b|PowerShell_profile"
      r"|CurrentVersion\\Run|Start Menu\\Programs\\Startup|\breg\s+add\b|new-itemproperty[^\n]*\\run"
      r"|\.config/autostart|sitecustomize\.py|usercustomize\.py"
      r"|\b(startup_enabled|run_on_startup|autostart|auto_start|run_at_login|start_on_boot)[\"']?\s*[:=]\s*[\"']?(true|yes|1)\b",
      "Makes something start automatically later, outside the agent session.", mention="low"),
    r("PRIV-ESC", "privilege", "high",
      r"\bnet\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators\s+\S+\s+/add|\buseradd\b|usermod\s+-a?G\s+(sudo|wheel|root)"
      r"|/etc/sudoers|NOPASSWD|\bS_ISUID\b|chmod\s+(u\+s|[24][0-7]{3})\b|setuid\s*\(\s*0\s*\)|authorized_keys"
      r"|/etc/passwd[^\n]*(>>|write|open\([^\n]*[\"']a)",
      "Creates admin users, adds SSH keys or sets SUID: takes control of the machine.", mention="low"),

    # Tampering with the agent itself.
    r("AGENT-BYPASS", "agent-config", "critical",
      r"dangerously-skip-permissions|bypassPermissions|--yolo\b|dangerously_skip|skip-permissions"
      r"|dangerously-bypass-approvals-and-sandbox|danger-full-access|approval_policy\s*=\s*[\"']never[\"']"
      r"|--approval-mode[=\s]+yolo|[\"']autoAccept[\"']\s*:\s*true",
      "Turns off the agent's permission prompts or sandbox, so it acts without asking you.", mention="low"),
    r("AGENT-CONFIG", "agent-config", "high",
      r"\.claude[/\\]settings(\.local)?\.json|[\"']hooks[\"']\s*:|PreToolUse|PostToolUse|UserPromptSubmit|SessionStart"
      r"|[\"']mcpServers[\"']|\.mcp\.json|claude_desktop_config\.json|[\"']permissions[\"']\s*:\s*\{|allowedTools"
      r"|\.codex[/\\]config\.toml|\[mcp_servers|\.cursor[/\\](mcp\.json|hooks\.json)|\.gemini[/\\]settings\.json"
      r"|\.vscode[/\\](settings|mcp)\.json|\.windsurf[/\\]|\.continue[/\\]config",
      "Edits agent settings, hooks or MCP servers (Claude, Codex, Cursor, Gemini, VS Code and others)."
      " Hooks run automatically on every action.", mention="low", doc="medium"),
    r("AGENT-MEMORY", "agent-config", "medium",
      r"(write|append|edit|modify|add)[^\n]{0,40}(CLAUDE\.md|AGENTS\.md|GEMINI\.md|MEMORY\.md|\.cursorrules"
      r"|\.cursor[/\\]rules|copilot-instructions\.md|\.windsurfrules)",
      "Changes the agent's standing instructions or memory, which affects every later session."),

    # Prompt injection: instructions aimed at the agent, against the user.
    r("INJ-OVERRIDE", "prompt-injection", "high",
      r"(ignore|disregard|forget|bypass)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|other|existing|your)\s+(\w+\s+){0,2}"
      r"(instructions|rules|prompts|protocols|constraints|guidelines|directives|restrictions|guardrails)"
      r"|disregard\s+(the\s+)?(system|previous|above)|override\s+(all\s+)?(your|the|prior|previous|existing|any)\s+(\w+\s+){0,2}"
      r"(instructions|rules|safety|constraints|protocols|directives|guidelines)"
      r"|(prior|previous|all|existing)\s+(\w+\s+){0,2}(directives|instructions|guidelines|rules)\s+(are|is|shall\s+be|have\s+been|were)\s+"
      r"(superseded|overridden|void|revoked|replaced|suspended)|superseded\s+by\s+this|instruction\s+override"
      r"|you\s+are\s+no\s+longer|new\s+system\s+prompt|jailbreak|developer\s+mode\s+(enabled|on)|\bDAN\b\s+(mode|prompt)",
      "Tries to override the agent's rules.", mention="low"),
    r("INJ-STEALTH", "prompt-injection", "high",
      r"(do\s*not|don'?t|never)\s+(tell|inform|mention|show|reveal|notify|disclose)\s+(this\s+|it\s+|that\s+)?(to\s+)?the\s+user"
      r"|without\s+(asking|telling|notifying|informing|alerting)\s+the\s+user"
      r"|(do\s*not|don'?t)\s+ask\s+(the\s+user\s+)?for\s+(permission|confirmation|approval)"
      r"|hide\s+(this|it)\s+from\s+the\s+user|keep\s+(this|it)\s+(secret|hidden)\s+from",
      "Tells the agent to act behind the user's back.", mention="low"),
    r("INJ-QUIET", "prompt-injection", "medium",
      r"\b(silently|secretly|covertly|quietly)\s+(run|send|upload|copy|install|execute|delete|read|forward|transmit|collect)",
      "Asks for a quiet action. Check why it should not be visible.", mention="low"),
    r("INJ-LEAK", "prompt-injection", "high",
      r"(reveal|disclose|output|print|repeat|share|display|dump|expose|leak|recite)\s+(\w+\s+){0,4}"
      r"(system\s+prompt|initial\s+instructions|hidden\s+instructions|system\s+instructions|configuration\s+directives"
      r"|confidential\s+(data|information)|internal\s+instructions|your\s+(full\s+)?instructions)"
      r"|system\s+prompt\s+(disclosure|configuration|extraction)\s+protocol",
      "Asks the agent to reveal its system prompt or confidential data.", mention="low"),
    r("INJ-ROLE", "prompt-injection", "high",
      r"introduc(e|ing)\s+yourself\s+as\s+(?-i:[A-Z][a-z]+\s+[A-Z])"
      r"|(assum|adopt|maintain|tak)\w*\s+(and\s+\w+\s+)?(on\s+)?(the\s+)?(identity|persona|role)\s+of\s+(?-i:[A-Z][a-z]+\s+[A-Z][a-z]+)"
      r"|(standpoint|perspective|persona)\s+of\s+(?-i:[A-Z][a-z]+\s+[A-Z][a-z]+),?\s+(a|an|the)\s|identity\s+binding|you\s+are\s+not\s+(an?\s+)?(ai|language\s+model|machine|assistant)"
      r"|you\s+are\s+(a\s+)?real\s+(human|person)|your\s+(true|real|new)\s+(identity|role|name|purpose)\s+is"
      r"|from\s+now\s+on,?\s+you\s+(are|will\s+(act|be|respond))|pretend\s+(to\s+be|you\s+are)\s+(a\s+)?(human|person|unrestricted)"
      r"|you\s+are\s+free\s+to\s+do\s+whatever|act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored|evil|jailbroken)",
      "Replaces the agent's identity or role.", mention="low", flags=re.IGNORECASE),
    r("INJ-SAFETY", "prompt-injection", "high",
      r"bypass(ing)?\s+(\w+\s+){0,2}(security|safety)\s+(protocols|filters|measures|guardrails|checks|restrictions)"
      r"|without\s+(any\s+)?(ethical|moral|safety|content)\s+(constraints|restrictions|guidelines|considerations|limits|filters)"
      r"|(no|without)\s+(ethical|moral|content)\s+(restrictions|limits|filters|boundaries)"
      r"|(never|do\s*not|don'?t)\s+refuse|(ignore|disable|remove|skip)\s+(all\s+)?(safety|content)\s+(filters|warnings|guidelines|checks)"
      r"|\buncensored\b|no\s+(disclaimers?|warnings?)\s+(should|must|shall)|(omit|remove|never\s+include)\s+(any\s+)?(disclaimers?|safety\s+warnings)",
      "Tells the agent to drop its safety rules or never refuse.", mention="low"),
    r("INJ-HIJACK", "prompt-injection", "high",
      r"begin\s+a\s+new\s+task|(instead\s+of|regardless\s+of)\s+(what\s+)?the\s+user('s)?\s+(asks?|requests?|wants?|says?|instructions?)"
      r"|(drop|abandon|stop)\s+(the\s+)?(current|user'?s?)\s+task|your\s+(real|actual|primary|true)\s+(task|goal|objective)\s+is",
      "Redirects the agent away from what the user asked.", mention="low"),
    r("INJ-AUTHORITY", "prompt-injection", "medium",
      r"(established|mandated|required|issued|certified)\s+by\s+the\s+(?-i:(International|Global|National|World|Federal)\s+[A-Z]\w+)"
      r"|operates?\s+under\s+the\s+(?-i:[A-Z][\w-]*(\s+[A-Z][\w-]*){1,5}\s+(Framework|Protocol|Standard|Standards|Directive))"
      r"|\b(Anthropic|OpenAI|system|admin(istrator)?)\s+(requires|mandates|override)\b",
      "Claims an outside authority to make the agent follow extra rules. Check whether that authority is real."),
    r("INJ-STEER", "prompt-injection", "medium",
      r"(you\s+(are\s+required\s+to|must|shall)|always|be\s+sure\s+to)\s+(emphasize|present|state|claim|assert|recommend|promote"
      r"|describe|portray|frame|position|rank|insist|suggest)\s+[^.\n]{0,120}"
      r"\b(equivalent|superior|proven|guaranteed|safe|effective|best|only|better|endorsed|clinically|scientifically|no\s+risk)\b"
      r"|(never|do\s*not|don'?t)\s+(mention|cite|recommend|disclose)\s+[^.\n]{0,40}\b(competitor|alternative|risk|side\s+effects?|downside)",
      "Steers what the agent tells the user (one-sided claims, hidden risks)."),
    r("INJ-URGENT", "prompt-injection", "low",
      r"^\s*[*_>#\s]*(IMPORTANT|CRITICAL|MANDATORY|NOTE|ATTENTION|SYSTEM)\s*[:!][^\n]{0,200}\b(agent|assistant|you|ai)\b"
      r"|upon\s+(system\s+)?initiali[sz]ation,?\s+the\s+(agent|assistant|system)",
      "Urgent directive addressed to the agent.", flags=re.MULTILINE | re.IGNORECASE),
    r("INJ-PERSONA", "prompt-injection", "medium",
      r"(operate|act|respond|speak|answer|engage)\w*\s+(from\s+the\s+(\w+\s+)?(standpoint|perspective|persona|viewpoint)\s+of|as)\s+"
      r"(?-i:[A-Z][a-z]+\s+[A-Z][a-z]+)\b|(maintain|keep|adopt|assume)\w*\s+(a\s+|its\s+|this\s+|the\s+|your\s+)?(\w+\s+){0,4}"
      r"(identity|persona)\s+(throughout|across|in\s+all)|\bsystem\s+identity\s*:|\b(mentor|operator|persona)\s+identity\b",
      "Gives the agent a fixed persona or identity. Legitimate skills rarely need this."),
    r("INJ-LEAK2", "prompt-injection", "high",
      r"(reproduc|recit|restat|output|print|repeat|quot|transcrib)\w*\s+(\w+\s+){0,6}(governing|primary|original|initial|underlying"
      r"|complete|full|entire|verbatim)\s+(\w+\s+){0,2}(instructions?|directives?|prompts?|configuration)"
      r"|begin\s+(your\s+|the\s+|each\s+)?(output|response|reply|answer)\s+with\s+(the\s+|a\s+)?(full|exact|verbatim|complete|entire)",
      "Asks the agent to reproduce its own instructions word for word.", mention="low"),
    r("INJ-META", "prompt-injection", "low",
      r"\bthe\s+(agent|assistant|ai|model)\s+(shall|must|is\s+required\s+to|will\s+always)\b",
      "Instructions about the agent itself, not about the task."),

    # Destructive commands.
    r("DESTROY", "destructive", "high",
      r"rm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(/|~|\$HOME|\*|\.\.)(\s|$)|remove-item[^\n]*-recurse[^\n]*-force[^\n]*(\\|~|\$env:|c:)"
      r"|del\s+/[sq]\s+/[sq]|format\s+[a-z]:|mkfs\.|dd\s+if=[^\n]*of=/dev/|shutil\.rmtree\s*\(\s*['\"]?(/|~|os\.path\.expanduser)"
      r"|git\s+push\s+(-f|--force)|drop\s+(table|database)|cipher\s+/w",
      "Can delete data that cannot be recovered.", mention="low"),

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


DOC_EXT = {".md", ".markdown", ".txt", ".mdx", ".rst"}
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat",
            ".cmd", ".rb", ".pl", ".go", ".rs", ".php", ".lua", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Official installers that docs commonly pipe to a shell. Still reported, at medium.
TRUSTED_INSTALLERS = re.compile(
    r"https?://(sh\.rustup\.rs|astral\.sh/|bun\.sh/|deno\.land/|get\.docker\.com|raw\.githubusercontent\.com/(Homebrew|nvm-sh)/"
    r"|ollama\.com/install|claude\.ai/install|get\.pnpm\.io|install\.python-poetry\.org|starship\.rs/|fnm\.vercel\.app"
    r"|tailscale\.com/install|get\.helm\.sh|sdk\.cloud\.google\.com|deb\.nodesource\.com|rpm\.nodesource\.com|pyenv\.run"
    r"|get\.k3s\.io|opencode\.ai/install|cli\.github\.com|brew\.sh|install\.determinate\.systems|nixos\.org/nix/install)", re.I)
QUOTED = re.compile(r"\"[^\"\n]{2,}\"|“[^”\n]{2,}”|‘[^’\n]{2,}’|`[^`\n]{2,}`")
EXAMPLE_HEADING = re.compile(
    r"detect|example|attack|threat|pattern|red\s+flag|warning\s+sign|what\s+(it|we|this)\s+(catch|flag|block)|indicator"
    r"|malicious|vulnerab|anti-?pattern|don'?t|avoid|never|blocked|forbidden|prohibited|scan|audit|injection", re.I)
BENIGN_PKG_HOOK = re.compile(
    r":\s*[\"']((npm|pnpm|yarn|bun)\s+(run\s+)?[\w:.-]+|husky(\s+install)?|tsc(\s+[\w./-]+)*|patch-package|node-gyp\s+rebuild"
    r"|prisma\s+generate|ngcc|npx\s+only-allow\s+\w+|lefthook\s+install|simple-git-hooks|electron-builder\s+install-app-deps)[\"']", re.I)
PERSIST_BENIGN_LINE = re.compile(
    r"crontab\s+-l(?![^\n]*\|\s*crontab)|crontab\s+-e\b|^\s*(source|\.)\s+~/|export\s+PATH|PATH=|alias\s+[\w-]+=|eval\s+\"\$\("
    r"|completion|nvm\.sh|conda\s+init|pyenv\s+init|starship\s+init|zoxide\s+init", re.I)
EXAMPLE_PATH = re.compile(r"(^|/)(examples?|samples?|tests?|fixtures?|threats?|attacks?)(/|[-_.])|injection|red[-_]?team|patterns?\.md$", re.I)
DETECTOR_LINE = re.compile(r"re\.compile\s*\(|new\s+RegExp\s*\(|[\"'](pattern|regex|regexp)[\"']\s*:|\bpatterns?\s*=\s*\[|\\s[+*]|\\b", re.I)
NEGATED = re.compile(r"\b(never|not|don'?t|do\s+not|without)\b[^.\n]{0,30}$", re.I)


def fenced_lines(lines: list[str]) -> set[int]:
    inside, out, marker = False, set(), ""
    for i, line in enumerate(lines, 1):
        s = line.lstrip()
        if s.startswith(("```", "~~~")):
            if not inside:
                inside, marker = True, s[:3]
            elif s.startswith(marker):
                inside = False
            out.add(i)
            continue
        if inside:
            out.add(i)
    return out


def heading_above(lines: list[str], ln: int) -> str:
    for i in range(ln - 1, max(-1, ln - 60), -1):
        s = lines[i].lstrip() if i < len(lines) else ""
        if s.startswith("#"):
            return s
    return ""


def adjust(rule: Rule, m, text: str, lines: list, ln: int, is_doc: bool, fence: set, rel: str = "") -> str | None:
    """Severity for one match, given where it sits. None drops the match."""
    line = lines[ln - 1] if 0 < ln <= len(lines) else ""
    sev = rule.severity
    prose = is_doc and ln not in fence
    if rule.id == "PKG-HOOK" and BENIGN_PKG_HOOK.search(line):
        return "low"
    if rule.id == "RCE-PIPE" and TRUSTED_INSTALLERS.search(line):
        return "medium"
    if rule.id == "PERSIST" and PERSIST_BENIGN_LINE.search(line):
        return "low"
    if rule.id == "RCE-PIPE" and not re.search(r"\w\.\w|\$\w|https?:", m.group(0)):
        return "low"  # "curl | sh" named as a pattern, no actual source
    if rule.id in ("WALLET", "INJ-SAFETY", "INJ-HIJACK", "INJ-LEAK", "INJ-ROLE", "INJ-OVERRIDE") \
            and NEGATED.search(text[max(0, m.start() - 40):m.start()]):
        if rule.id == "WALLET" or prose:
            return "low"
    if is_doc and rule.mention and EXAMPLE_PATH.search(rel):
        return rule.mention
    if is_doc and rule.doc and SEV_ORDER[rule.doc] < SEV_ORDER[sev]:
        sev = rule.doc
    # Scanners and linters list attack patterns as regex strings; payloads are not written that way.
    if not is_doc and rule.mention and DETECTOR_LINE.search(line):
        return rule.mention
    if prose and rule.mention:
        col = m.start() - (text.rfind("\n", 0, m.start()) + 1)
        quoted = any(q.start() <= col < q.end() for q in QUOTED.finditer(line))
        table = line.lstrip().startswith("|")
        example = bool(EXAMPLE_HEADING.search(heading_above(lines, ln)))
        if quoted or table or example:
            sev = rule.mention
    return sev


COMBO_DOWNLOAD = re.compile(r"requests\.get|urlopen|urlretrieve|\bcurl\s|\bwget\s|\bfetch\s*\(|invoke-webrequest|\biwr\s|httpx\.(get|stream)"
                            r"|http\.get\s*\(|downloadfile|net\.webclient|git\s+clone", re.I)
COMBO_WRITEBIN = re.compile(r"open\s*\([^\n)]*[\"']wb|write_bytes|\s-o\s|\s-O\s|-outfile|>\s*[\w/.$~-]+\s*(&&|;|$)|downloadfile", re.I | re.M)
COMBO_MKEXEC = re.compile(r"chmod\s+(\+x|u\+x|[0-7]?7[0-7]{2})|os\.chmod|S_IX|0o7[0-7]{2}", re.I)
COMBO_RUN = re.compile(r"subprocess|os\.system|popen|\bexec[lv]?p?e?\s*\(|start-process|os\.startfile|&&\s*\./|^\s*\./|\bsh\s+[\w/.$~-]+\.sh|\bbash\s+[\w/.$~-]+", re.I | re.M)
# Strong secret sources: no ordinary API client needs these.
COMBO_SECRET = re.compile(r"\.ssh(?=[/\\\"'])|id_rsa|id_ed25519|\.aws[/\\]credentials|security\s+find-|\.git-credentials|\.netrc"
                          r"|login\s*data|cookies\.sqlite|key4\.db|wallet\.dat|keystore[/\\]|solana[/\\]id\.json|exodus[/\\]|electrum[/\\]"
                          r"|dict\s*\(\s*os\.environ\s*\)|json\.dumps\s*\(\s*(dict\s*\()?os\.environ|os\.environ\.items\s*\(\)\s*\}?\s*\)?"
                          r"|JSON\.stringify\s*\(\s*process\.env|/etc/passwd|/etc/shadow|\.kube[/\\]config|\.docker[/\\]config"
                          r"|\.bash_history|\.zsh_history|clipboard|ImageGrab|screenshot\(", re.I)
# Weak secret sources: normal for API clients, suspicious only with a suspicious destination.
COMBO_SECRET_WEAK = re.compile(r"\.env\b|load_dotenv|os\.environ|process\.env|getenv\s*\(|api[_-]?key|token|password", re.I)
COMBO_BAD_DEST = re.compile(r"http://(?!localhost|127\.|0\.0\.0\.0|\[::1\])|webhook\.site|requestbin|pipedream|ngrok|trycloudflare"
                            r"|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin|transfer\.sh|0x0\.st|\.onion\b"
                            r"|\.(xyz|top|tk|ml|ga|cf|gq|ru|su|site|online|click|icu|pw)(/|[\"':])", re.I)
COMBO_SEND = re.compile(r"requests\.(post|put)|urlopen\s*\([^\n]*data\s*=|method\s*:\s*[\"']post|curl[^\n]*\s(-d|--data[\w-]*|-F|-T|--upload-file)\s"
                        r"|socket\.(send|sendall|connect)|smtplib|ftplib|paramiko|httpx\.post|axios\.post|invoke-restmethod[^\n]*-method\s+post", re.I)
COMBO_CRYPT = re.compile(r"\bFernet\b|AES\.new|Cipher\s*\(|\.encrypt\s*\(|createCipheriv", re.I)
COMBO_WALK = re.compile(r"os\.walk|\.rglob\(|glob\.glob\([^\n]*\*\*|Path\.home\(\)|expanduser\(\s*[\"']~|readdirSync|Get-ChildItem[^\n]*-Recurse", re.I)
COMBO_CLOBBER = re.compile(r"os\.remove|\.unlink\(|os\.rename|\.rename\(|shutil\.move|\.replace\(\s*\w+\s*,|write_bytes|open\s*\([^\n)]*[\"']wb", re.I)
COMBO_STARTUP = re.compile(r"\b(startup|autostart|auto_start|on_start|run_on_load|SessionStart|PreToolUse|onStartup|boot)\w*[\"']?\s*[:=]", re.I)
COMBO_REMOTE = re.compile(r"https?://|git@|\.git\b", re.I)


def combos(rel: str, text: str, lines: list, is_doc: bool, fence: set, report: Report) -> None:
    """Capabilities that are normal alone but malicious together, judged per file.
    In documentation only fenced code counts (that is what an agent would run)."""
    body = "\n".join(lines[i - 1] for i in sorted(fence)) if is_doc else text
    if not body.strip():
        return
    add = lambda sev, rid, why: report.findings.append(Finding(sev, "combination", rid, rel, 0, why))
    bad_dest = bool(COMBO_BAD_DEST.search(body) or RAW_IP_RE.search(body))
    if COMBO_DOWNLOAD.search(body) and COMBO_MKEXEC.search(body) and COMBO_RUN.search(body):
        if not is_doc:
            add("critical", "COMBO-DROPPER", "Downloads something, makes it executable and runs it.")
        elif bad_dest:
            add("high", "COMBO-DROPPER", "Instructions download a program from a suspicious address, make it executable and run it.")
        elif not TRUSTED_INSTALLERS.search(body):
            add("medium", "COMBO-DROPPER", "Instructions download a program, make it executable and run it. Check the source.")
    elif COMBO_DOWNLOAD.search(body) and COMBO_WRITEBIN.search(body) and COMBO_RUN.search(body) and RAW_IP_RE.search(body):
        add("high", "COMBO-DROPPER", "Downloads from a raw IP address, saves it and runs something.")
    if COMBO_SEND.search(body) and (COMBO_SECRET.search(body) or (bad_dest and COMBO_SECRET_WEAK.search(body))):
        add("high", "COMBO-EXFIL", "Reads secrets (keys, credentials, browser or wallet data, all env vars) and sends data out.")
    if COMBO_CRYPT.search(body) and COMBO_WALK.search(body) and COMBO_CLOBBER.search(body):
        add("high", "COMBO-RANSOM", "Encrypts files across your folders and replaces or deletes the originals.")
    if COMBO_STARTUP.search(body) and COMBO_REMOTE.search(body) and COMBO_RUN.search(body):
        add("high", "COMBO-STARTUP", "Registers something to run on startup that comes from a remote source.")


B64_STRING = re.compile(r"[\"'`]([A-Za-z0-9+/]{40,}={0,2})[\"'`]|base64\s+-d[^\n]*?([A-Za-z0-9+/]{40,}={0,2})")


def decoded_scan(rel: str, text: str, report: Report) -> None:
    """Decode base64 strings and look for dangerous content hidden inside (one level)."""
    import base64
    seen = 0
    for m in B64_STRING.finditer(text):
        blob = m.group(1) or m.group(2)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        dec = raw.decode("utf-8", errors="ignore")
        if len(dec) < 0.8 * len(raw) or sum(c.isprintable() or c in "\n\t" for c in dec) < 0.9 * max(1, len(dec)):
            continue
        for rule in RULES:
            if RANK[rule.severity] >= RANK["high"] and rule.category != "prompt-injection" and rule.pattern.search(dec):
                report.findings.append(Finding("critical", "obfuscation", "HIDDEN-" + rule.id, rel, line_of(text, m.start()),
                                               "Base64-encoded text hides: " + rule.why, clip(dec, 100)))
                break
        else:
            if re.search(r"https?://|\b(sh|bash|powershell|cmd)\b|import\s+\w+|exec|eval", dec):
                report.findings.append(Finding("high", "obfuscation", "HIDDEN-CODE", rel, line_of(text, m.start()),
                                               "Base64-encoded command or address. Code that hides what it does is a red flag.",
                                               clip(dec, 100)))
        seen += 1
        if seen >= 20:
            break


RAW_IP_RE = re.compile(r"(https?://|[\"'])(?!(10|127|0)\.)(?!192\.168\.)(?!172\.(1[6-9]|2\d|3[01])\.)(\d{1,3}\.){3}\d{1,3}")


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
    is_doc = ext in DOC_EXT or PurePosixPath(rel).name.upper().startswith(("README", "CHANGELOG"))
    fence = fenced_lines(lines) if is_doc else set()
    for rule in RULES:
        if rule.id == "PKG-HOOK" and PurePosixPath(rel).name != "package.json":
            continue
        hits = list(rule.pattern.finditer(text))
        kept = 0
        for m in hits:
            g = m.group(0)
            ln = line_of(text, m.start() + len(g) - len(g.lstrip()))
            line_text = lines[ln - 1] if ln <= len(lines) else ""
            sev = adjust(rule, m, text, lines, ln, is_doc, fence, rel)
            if sev is None:
                continue
            kept += 1
            if kept <= MAX_HITS_PER_RULE_PER_FILE:
                report.findings.append(Finding(sev, rule.category, rule.id, rel, ln, rule.why, clip(line_text)))
        if kept > MAX_HITS_PER_RULE_PER_FILE:
            report.findings.append(Finding("info", rule.category, rule.id, rel, 0,
                                           f"{kept - MAX_HITS_PER_RULE_PER_FILE} more match(es) of {rule.id} in this file."))
    if is_doc or ext in CODE_EXT:
        combos(rel, text, lines, is_doc, fence, report)
    decoded_scan(rel, text, report)

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
    # Weak signals that add up: several different soft prompt-injection cues in one file.
    soft = {"INJ-AUTHORITY", "INJ-STEER", "INJ-QUIET", "INJ-URGENT", "INJ-PERSONA", "INJ-META", "AGENT-MEMORY", "HTML-COMMENT",
            "ZERO-WIDTH", "RAW-IP"}
    per_file: dict = {}
    for f in report.findings:
        if f.rule in soft and f.severity in ("low", "medium"):
            per_file.setdefault(f.file, set()).add(f.rule)
    for fname, rules in per_file.items():
        if len(rules) >= 2 and rules != {"INJ-URGENT", "RAW-IP"}:
            report.findings.append(Finding("high", "combination", "COMBO-INJECT", fname, 0,
                                           "Several separate manipulation cues in one file: " + ", ".join(sorted(rules)) + "."))
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
    print(f"ai-skill-guard {rep.version}  |  {rep.target}")
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
    ap = argparse.ArgumentParser(prog="ai-skill-guard", description="Static safety check for AI agent skills. Never runs the code it scans.")
    ap.add_argument("path", help="skill folder, plugin folder, single file, or .zip/.skill archive")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITIES[1:] + ["never"],
                    help="lowest severity that makes the exit code 1 (default: high)")
    ap.add_argument("--version", action="version", version=f"ai-skill-guard {__version__}")
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
