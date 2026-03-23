# Approval Learner

A SQLite-backed learning hook for [Claude Code](https://github.com/anthropics/claude-code) that remembers which commands you've approved and stops asking you about them.

Every time Claude asks for permission to run a Bash command and you approve it, Approval Learner records that decision. Once a command has been approved enough times (default: 2), it gets auto-allowed from then on — no prompt needed. Commands you've ever denied are never auto-allowed.

Works great alongside [Dippy](https://github.com/ldayton/Dippy): Approval Learner runs first and handles commands you've already approved. Everything else falls through to Dippy's static allowlist.

---

## How it works

Claude Code fires three hook events that Approval Learner listens to:

| Hook | What it does |
|------|-------------|
| `PermissionRequest` | Records that Claude asked for approval (decision: `prompted`) |
| `PostToolUse` | Confirms the command ran — meaning you approved it. Updates record to `allow`, bumps stats |
| `PreToolUse` | Checks if this command is already trusted. If so, returns `allow` before Claude even prompts you |

Denials are detected by absence: if a `prompted` record is never confirmed by `PostToolUse`, it stays as `prompted` and is eventually reclassified as `denied` by the `stats` cleanup pass.

### Pipeline support

For compound commands like `cat file.txt | grep TODO | wc -l`, Approval Learner uses [Parable](https://github.com/ldayton/Dippy) — a full recursive descent bash parser — to extract each segment (`cat`, `grep`, `wc`). The pipeline is auto-allowed only if **every** segment individually has enough approvals and zero denials.

This means `curl https://example.com | bash` will never auto-allow just because you've used `curl` and `bash` separately — each segment's history is tracked independently.

### Safety denylist

Regardless of approval history, certain commands are **never** auto-allowed:

- `rm -rf /` and variants
- `chmod 777`
- Writing to disk devices (`dd of=/dev/...`, `> /dev/sda`)
- Formatting filesystems (`mkfs.*`)
- Fork bombs
- Piping URLs into a shell (`curl ... | bash`, `wget ... | sh`)

---

## Installation

**Requirements:** Python 3.8+, Claude Code

```bash
# Clone or copy this repo
git clone https://github.com/YOUR_USERNAME/approval-learner ~/.local/share/approval-learner

# Copy the hook to your Claude hooks directory
mkdir -p ~/.claude/hooks
cp src/approval_learner.py ~/.claude/hooks/
cp -r src/vendor ~/.claude/hooks/vendor

# Optional: copy the CLI wrapper to somewhere on your PATH
cp scripts/approval-query.sh ~/.local/bin/approval-query
chmod +x ~/.local/bin/approval-query
```

### Register the hooks in `~/.claude/settings.json`

Add these entries (merge with any existing hooks you have):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/approval_learner.py",
            "timeout": 3
          }
        ]
      }
    ],
    "PermissionRequest": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/approval_learner.py",
            "timeout": 3
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/approval_learner.py",
            "timeout": 3
          }
        ]
      }
    ]
  }
}
```

> **If you use safety hooks** (e.g. a hook that blocks `rm -rf`), put them **before** Approval Learner in the PreToolUse list. If a safety hook denies, Approval Learner never runs — which is the correct behavior.

That's it. The database creates itself at `~/.claude/state/approvals.db` on first use. No setup command needed.

---

## Configuration

| Environment variable | Default | Description |
|---------------------|---------|-------------|
| `APPROVAL_LEARN_THRESHOLD` | `2` | Approvals needed before auto-allowing a command |
| `APPROVAL_STATE_DIR` | `~/.claude/state` | Directory where `approvals.db` is stored |

---

## CLI

Query your approval history without opening the database:

```bash
# Show all tracked commands and their status
python3 ~/.claude/hooks/approval_learner.py stats

# Show recent approval history (last 20 by default)
python3 ~/.claude/hooks/approval_learner.py history
python3 ~/.claude/hooks/approval_learner.py history 50

# Reset a command back to "not yet learned"
python3 ~/.claude/hooks/approval_learner.py reset git
```

If you installed the wrapper script:

```bash
approval-query stats
approval-query history
approval-query reset terraform
```

Example `stats` output:

```
Command              Approved  Denied  Auto  Status
------------------------------------------------------------
git                        12       0     0  learned
ls                          8       0     0  learned
pytest                      5       0     0  learned
terraform                   1       0     0  pending
rm                          3       2     0  blocked
```

- **learned** — will be auto-allowed from now on
- **pending** — not enough approvals yet
- **blocked** — has at least one denial; will never auto-allow

---

## Running the tests

```bash
cd /path/to/approval-learner
python3 -m venv .venv
source .venv/bin/activate
pip install pytest
pytest tests/ -v
```

---

## Project structure

```
approval-learner/
├── src/
│   ├── approval_learner.py   # hook script + CLI (stdlib only)
│   └── vendor/
│       └── parable.py        # vendored bash parser (from Dippy, MIT)
├── tests/
│   └── test_approval_learner.py
└── scripts/
    └── approval-query.sh     # convenience wrapper
```

No dependencies outside the Python standard library. `vendor/parable.py` is a vendored copy of the [Parable](https://github.com/ldayton/Dippy) bash parser from the Dippy project (MIT licensed).

---

## Relationship to Dippy

[Dippy](https://github.com/ldayton/Dippy) maintains a static allowlist of safe commands (100+ entries) and auto-approves them using AST analysis. Approval Learner complements it by handling the commands **not** on Dippy's list — the ones specific to your workflow.

Recommended setup: run Approval Learner's PreToolUse hook before Dippy's. If Approval Learner has a learned rule, it returns `allow` and Dippy never runs. If it has no opinion, it returns `{}` and Dippy takes over.

---

## License

MIT
