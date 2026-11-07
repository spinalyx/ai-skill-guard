# skill-guard

A static safety check for AI agent skills (Claude Code / Agent Skills, plugins, prompt packs) **before you install them**.

It reads every file in a skill folder or `.zip` / `.skill` archive and flags known red flags. It never runs, imports or installs anything it scans. One file, Python 3.9+, standard library only.

```bash
python skill_guard.py path/to/skill            # human-readable report
python skill_guard.py path/to/skill --json     # machine-readable
python skill_guard.py skill.zip --fail-on medium
```

Exit codes: `0` nothing at or above `--fail-on` (default `high`), `1` findings at or above it, `2` error. Use it in CI to block a skill from being added to a shared repo.

## What it looks for

| Category | Examples |
|---|---|
| remote-exec | `curl … \| bash`, `iwr … \| iex`, `DownloadString` |
| obfuscation | base64-decode-and-run, `-EncodedCommand`, `marshal.loads`, long encoded blobs |
| exfiltration | webhook.site, requestbin, ngrok, Discord/Telegram bot webhooks, pastebin |
| credentials | `~/.ssh`, `~/.aws/credentials`, `.env`, `gh auth token`, Keychain, Credential Manager |
| browser-data | Chrome/Firefox cookie and login databases, cookie-extraction libraries |
| persistence | cron, `schtasks`, LaunchAgents, systemd, shell profiles, registry `Run` keys |
| agent-config | `--dangerously-skip-permissions`, `bypassPermissions`, hooks, `mcpServers`, settings files, `allowed-tools: Bash` |
| prompt-injection | "ignore previous instructions", "do not tell the user", "silently send…" |
| hidden-text | invisible Unicode tag characters (decoded for you), zero-width and bidi characters, instruction-like HTML comments |
| destructive | `rm -rf /`, `Remove-Item -Recurse -Force`, `git push --force`, `DROP TABLE` |
| privilege | `sudo`, execution-policy bypass, Defender exclusions, firewall off |
| supply-chain | `pip`/`npm`/`npx` installs, `postinstall` hooks in `package.json` |
| filesystem / binary | executables, nested archives, symlinks leaving the folder, zip-slip paths |

It also lists every network host the skill mentions, so you can see where data could go.

## What it cannot do

It matches patterns; it does not understand intent. A careful attacker can write something it misses, and a legitimate tool will trigger findings (a research skill *will* use the network). Treat every finding as a question for a human, and a clean report as "no known red flags", not "safe". Read [POLISA-BEZBEDNOSTI.md](POLISA-BEZBEDNOSTI.md) (Serbian) for the full policy: threats on a local machine and in the cloud, ten rules, a pre-install checklist and what to do if something bad got in.

Scanning this repository flags itself, because it contains every pattern it looks for.

## Tests

```bash
python -m unittest discover -s tests
```

## License

MIT. See [LICENSE](LICENSE).
