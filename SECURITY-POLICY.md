# Security policy for AI agent skills

**Version 0.1 · 7 November 2026**

This policy is for anyone who installs skills, plugins or MCP servers for AI agents (Claude Code, Claude Desktop, Cursor, Codex and the like). It is written for people who are not programmers but who decide what runs on their machine.

## 1. What a skill really is

A skill looks like a set of instructions: a `SKILL.md` text file and a few scripts. But the agent **carries out** those instructions with your permissions. It can read your files, run programs and send data to the internet, as far as you have allowed it.

Installing a skill means letting a stranger whisper instructions to your assistant. Most of those strangers mean well. This policy exists because of the rest.

> **No tool makes a skill completely safe.** Safety comes in layers: source, reading, automated checks, a small trial and limited permissions. When one layer fails, another catches the problem.

## 2. What can go wrong on your own machine

| Risk | What it looks like | Why it matters |
|---|---|---|
| **Stolen keys and passwords** | A script reads `.env`, `~/.ssh`, `~/.aws`, Windows Credential Manager or macOS Keychain | Someone spends your API credits, gets into your servers and your GitHub |
| **Stolen browser cookies** | "For better results, allow access to your browser cookies" | A cookie gets someone into your account with no password and no two-factor check: LinkedIn, Gmail, your bank |
| **Download and run** | `curl … \| bash`, `iwr … \| iex` | The code arrives at the moment it runs; nobody has read it, and tomorrow it can be different |
| **Hidden instructions (prompt injection)** | "Ignore previous instructions", "do not tell the user", text in HTML comments, invisible Unicode characters | You see harmless text; the agent reads an order |
| **Brakes turned off** | `--dangerously-skip-permissions`, `bypassPermissions`, edits to `settings.json` | From then on the agent acts without asking, for this skill and every other one |
| **Hooks** | A skill or plugin adds a hook to the agent settings | A hook runs by itself on every action, and keeps running after the skill is deleted unless someone removes it |
| **Persistence** | Scheduled tasks, the Startup folder, `.bashrc`, registry `Run` keys | Something starts even when the agent is not running |
| **Dependency chain** | `npm install`, `pip install`, `postinstall` scripts | You install one skill and twenty packages nobody reviewed come with it |
| **Deletion** | `rm -rf`, `Remove-Item -Recurse -Force`, `git push --force` | Data loss that cannot be undone |
| **Content leaving** | The skill sends your texts, images or documents to "its own" server | Confidential client material ends up with a third party |
| **Silent version change** | A skill from GitHub updates, and you never looked at what changed | What was clean yesterday may not be clean today |
| **Trigger hijacking** | An overly broad description ("always use this") or the same name as an existing skill | The wrong skill takes over your requests |

## 3. What also applies in the cloud

When the agent runs in the cloud (cloud sessions, CI/CD, GitHub Actions, shared team plugins), the risk moves but does not disappear:

- **Tokens in the environment.** A cloud session usually holds a GitHub token and project secrets. A malicious skill sees them just as it would locally.
- **Write access to the repository.** A skill can commit, open a PR or push code. That is how malicious code gets into a product.
- **Network egress.** If the sandbox has open internet access, data can go anywhere.
- **Shared skills in an organization.** One bad plugin reaches the whole team at once. Approval for an organization must be stricter than for one person.
- **Logs.** Secrets a script prints end up in logs that many people can read.

The cloud rule: **fewest secrets, least privilege, restricted network.** Give a cloud environment only the key it needs, with the shortest lifetime and the narrowest scope.

## 4. Rules

1. **Source.** Install from official sources or from authors with a track record, a license and an active repository. A skill from a DM, Discord or an unknown website is high risk by default.
2. **Read everything.** Not only `SKILL.md`, but every file in `scripts/`, `references/` and `hooks/`. If you cannot read code, have someone who can do it, or an agent in a separate session that does **not** have the skill installed.
3. **Scan.** Run `ai-skill-guard` before installing. Every `critical` or `high` finding needs an explanation before you continue.
4. **Pin the version.** Write down the exact commit or version you reviewed. Do not install "latest".
5. **An update is a new install.** Before updating, look at what changed and scan again.
6. **Never turn permissions off.** No `--dangerously-skip-permissions`, no "allow all". The agent should ask.
7. **Do not give a skill your cookies or passwords.** If a skill asks for browser cookies, the answer is NO. You enter keys yourself, into the environment, never into the chat.
8. **Start small.** Try a new skill on a test folder with no secrets. If it does something big, try it in a separate user account, a virtual machine or a container.
9. **Keep an inventory.** A list of what is installed: what it is, where it came from, which version, who approved it and when. Remove what nobody uses.
10. **One decision, one person.** For every skill, it is known who said "yes".

## 5. Pre-install checklist

- [ ] I know who the author is and where the skill comes from
- [ ] There is a license and it allows my use
- [ ] Every file has been read, not just the description
- [ ] `ai-skill-guard` shows no unresolved `critical` or `high` findings
- [ ] I know which internet addresses the skill sends data to, and why
- [ ] The skill does not ask for cookies, passwords or turning permissions off
- [ ] It does not add hooks, MCP servers or scheduled tasks without my knowledge
- [ ] The version is written down
- [ ] I tried it small first, with no secrets
- [ ] It is recorded in the inventory

## 6. If you suspect something bad got installed

1. Stop the agent session, and disconnect from the network if things are happening "by themselves".
2. Remove the skill and check whether it left hooks (`settings.json`), MCP servers, scheduled tasks or startup items behind.
3. **Rotate keys and passwords** it could have seen: API keys, GitHub tokens, and the passwords of accounts whose cookies were in the browser (sign out of all devices).
4. Check usage with your AI providers and recent commits in your repositories.
5. Write down what happened so it does not happen again.

## 7. Automated check: ai-skill-guard

`ai-skill-guard` is a small Python script with no dependencies. It reads a skill and looks for known dangerous patterns. **It never runs anything it scans.**

```bash
python ai_skill_guard.py path/to/skill
```

It checks for download-and-run commands, hidden and encoded code, throwaway endpoints used to receive stolen data, reading of keys, passwords and cookies, crypto wallets, persistence, changes to agent settings (hooks, MCP, permissions), hidden instructions and invisible Unicode characters, dangerous deletion, privilege escalation, package install hooks, executables, symbolic links and ZIP archives that write outside their folder. At the end it lists every internet address the skill mentions.

What it **cannot** do: understand intent, catch a completely new trick, or review packages the skill will download later. That is why it is layer 3 of 5, not a replacement for reading.

A clean result means "no known red flags". It does not mean "safe".
