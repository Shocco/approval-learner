# hooks/approval_learner.py
"""
Approval Learner — SQLite-backed learning layer for Claude Code tool approvals.

Logs PermissionRequest decisions, tracks command frequency, and auto-allows
commands that have been approved enough times with zero denials.

Works alongside Dippy: this hook runs first on PreToolUse. If it has a learned
rule, it emits allow. Otherwise it returns {} and Dippy handles it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

# --- Configuration ---

STATE_DIR = Path(os.environ.get(
    "APPROVAL_STATE_DIR",
    str(Path.home() / ".claude" / "state")
))
DB_PATH = STATE_DIR / "approvals.db"
LEARN_THRESHOLD = int(os.environ.get("APPROVAL_LEARN_THRESHOLD", "2"))

# --- Command Parsing ---

# Try to import Parable for AST-based parsing; fall back to shlex
try:
    _vendor_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
    if _vendor_dir not in sys.path:
        sys.path.insert(0, _vendor_dir)
    from parable import parse as parable_parse, ParseError
    HAS_PARABLE = True
except ImportError:
    HAS_PARABLE = False


def extract_base_commands(command: str) -> list[str]:
    """Extract all base command names from a (possibly compound) command.

    Uses Parable's AST for accurate parsing of pipelines, &&/||, subshells,
    command substitution, etc. Falls back to shlex-based splitting if Parable
    is not available.

    Returns:
        List of base command names, e.g. ["cat", "grep", "wc"] for
        "cat file.txt | grep foo | wc -l"
    """
    if HAS_PARABLE:
        return _extract_via_ast(command)
    return _extract_via_shlex(command)


def _extract_via_ast(command: str) -> list[str]:
    """Walk Parable AST to extract all base command names."""
    try:
        nodes = parable_parse(command)
    except Exception:
        return _extract_via_shlex(command)

    commands: list[str] = []
    _walk_nodes(nodes if isinstance(nodes, list) else [nodes], commands)
    return commands


def _walk_nodes(nodes: list, commands: list[str]) -> None:
    """Recursively walk AST nodes to collect command names."""
    for node in nodes:
        kind = getattr(node, "kind", None)

        if kind == "command":
            words = getattr(node, "words", [])
            if words:
                name = _word_to_str(words[0])
                if name:
                    base = Path(name).name
                    commands.append(base)
            # Recurse into command substitutions in word parts
            for word in words:
                for part in getattr(word, "parts", []):
                    part_kind = getattr(part, "kind", None)
                    if part_kind in ("cmdsub", "procsub"):
                        inner = getattr(part, "command", None)
                        if inner:
                            _walk_nodes([inner], commands)

        elif kind == "pipeline":
            _walk_nodes(getattr(node, "commands", []), commands)

        elif kind == "list":
            parts = getattr(node, "parts", [])
            _walk_nodes([p for p in parts if getattr(p, "kind", None) != "operator"], commands)

        elif kind in ("subshell", "brace_group"):
            body = getattr(node, "body", None)
            if body:
                _walk_nodes(body if isinstance(body, list) else [body], commands)

        elif kind in ("if", "while", "until"):
            for attr in ("condition", "body", "else_part"):
                child = getattr(node, attr, None)
                if child:
                    _walk_nodes(child if isinstance(child, list) else [child], commands)

        elif kind == "for":
            body = getattr(node, "body", None)
            if body:
                _walk_nodes(body if isinstance(body, list) else [body], commands)


def _word_to_str(word) -> str:
    """Convert a Parable Word node to a plain string (best effort)."""
    if isinstance(word, str):
        return word
    parts = getattr(word, "parts", [])
    result = []
    for part in parts:
        val = getattr(part, "value", None)
        if val is not None:
            result.append(str(val))
    return "".join(result) if result else getattr(word, "value", str(word))


def _extract_via_shlex(command: str) -> list[str]:
    """Fallback: split on shell operators and extract first word of each segment."""
    import re
    import shlex
    segments = re.split(r'\s*(?:\|\||&&|[|;])\s*', command)
    commands = []
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        if tokens:
            commands.append(Path(tokens[0]).name)
    return commands


# --- Database Layer ---


class ApprovalDB:
    """SQLite database for approval tracking with WAL mode for concurrency."""

    def __init__(self, db_path: str | Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(
            str(self.db_path),
            timeout=5,
        )
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                session_id TEXT,
                tool_name TEXT NOT NULL,
                command TEXT NOT NULL,
                command_hash TEXT NOT NULL,
                base_command TEXT NOT NULL,
                decision TEXT NOT NULL,
                working_dir TEXT,
                is_compound INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS command_stats (
                base_command TEXT PRIMARY KEY,
                approve_count INTEGER DEFAULT 0,
                deny_count INTEGER DEFAULT 0,
                last_approved REAL,
                last_denied REAL,
                auto_allowed INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_approvals_hash
                ON approvals(command_hash);
            CREATE INDEX IF NOT EXISTS idx_approvals_base
                ON approvals(base_command);
            CREATE INDEX IF NOT EXISTS idx_approvals_time
                ON approvals(timestamp);
        """)
        self.conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def close(self) -> None:
        self.conn.close()

    def record(
        self,
        tool_name: str,
        command: str,
        decision: str,
        working_dir: str = "",
    ) -> None:
        """Record an approval/denial decision.

        Args:
            tool_name: The Claude Code tool name (e.g. "Bash").
            command: The full command string that was approved or denied.
            decision: Either "allow" or "deny".
            working_dir: The working directory at the time of the decision.
        """
        base = self._extract_base_command(command)
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:16]
        is_compound = 1 if len(extract_base_commands(command)) > 1 else 0
        session_id = os.environ.get("CLAUDE_SESSION_ID", "")

        self.conn.execute(
            """INSERT INTO approvals
               (timestamp, session_id, tool_name, command, command_hash,
                base_command, decision, working_dir, is_compound)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (time.time(), session_id, tool_name, command, cmd_hash,
             base, decision, working_dir, is_compound),
        )

        if decision == "allow":
            self.conn.execute(
                """INSERT INTO command_stats (base_command, approve_count, last_approved)
                   VALUES (?, 1, ?)
                   ON CONFLICT(base_command) DO UPDATE SET
                     approve_count = approve_count + 1,
                     last_approved = ?""",
                (base, time.time(), time.time()),
            )
        elif decision == "deny":
            self.conn.execute(
                """INSERT INTO command_stats (base_command, deny_count, last_denied)
                   VALUES (?, 1, ?)
                   ON CONFLICT(base_command) DO UPDATE SET
                     deny_count = deny_count + 1,
                     last_denied = ?""",
                (base, time.time(), time.time()),
            )
        self.conn.commit()

    def get_stats(self, base_command: str) -> dict:
        """Get approval stats for a base command.

        Args:
            base_command: The base command name to look up (e.g. "git").

        Returns:
            A dict with keys: approve_count, deny_count, auto_allowed, and
            any other columns from command_stats. Returns zero-valued defaults
            if the command has never been seen.
        """
        row = self.conn.execute(
            "SELECT * FROM command_stats WHERE base_command = ?",
            (base_command,),
        ).fetchone()
        if row is None:
            return {"approve_count": 0, "deny_count": 0, "auto_allowed": 0}
        return dict(row)

    def should_auto_allow(self, base_command: str) -> bool:
        """Check if a base command has enough approvals and zero denials.

        Args:
            base_command: The base command name to check.

        Returns:
            True if approve_count >= LEARN_THRESHOLD and deny_count == 0.
        """
        stats = self.get_stats(base_command)
        return (
            stats["approve_count"] >= LEARN_THRESHOLD
            and stats["deny_count"] == 0
        )

    def should_auto_allow_compound(self, command: str) -> bool:
        """Check if all segments of a compound command are individually trusted."""
        base_commands = extract_base_commands(command)
        if not base_commands:
            return False
        return all(self.should_auto_allow(base) for base in base_commands)

    @staticmethod
    def _extract_base_command(command: str) -> str:
        """Extract the base command name (first word, no path).

        Skips leading environment variable assignments (FOO=bar cmd → cmd).

        Args:
            command: The full command string.

        Returns:
            The bare executable name, e.g. "/usr/bin/git status" → "git".
        """
        cmd = command.strip()
        parts = cmd.split()
        if not parts:
            return ""
        # Skip env var assignments: FOO=bar cmd
        idx = 0
        while idx < len(parts) and "=" in parts[idx]:
            idx += 1
        if idx >= len(parts):
            return ""
        first_word = parts[idx]
        return Path(first_word).name


# --- Hook Handlers ---


def handle_permission_request(input_data: dict, db_path: str | Path = DB_PATH):
    """Handle PermissionRequest hook: log the command that triggered approval prompt.

    At this point, the user hasn't decided yet. We log with decision='prompted'.
    The actual allow/deny is recorded by observing whether PostToolUse fires
    (approved) or not (denied/cancelled).

    We also record a compound command's segments individually.
    """
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")
    working_dir = tool_input.get("cwd", input_data.get("cwd", ""))

    if not command:
        return

    db = ApprovalDB(db_path)
    try:
        db.record(tool_name, command, "prompted", working_dir)
    finally:
        db.close()


# --- Safety Denylist ---
# Commands that should NEVER be auto-allowed regardless of approval history.

SAFETY_DENYLIST_PATTERNS = [
    r"rm\s+(-\w*)?r\w*\s+/\s*$",      # rm -rf /
    r"rm\s+(-\w*)?r\w*\s+/[a-z]+\s*$", # rm -rf /etc, /usr, etc.
    r"chmod\s+777",                      # world-writable
    r">\s*/dev/sd",                      # overwrite disk device
    r"mkfs\.",                           # format filesystem
    r"dd\s+.*of=/dev/",                  # raw write to device
    r":\(\)\s*\{\s*:\|:\s*&\s*\}",      # fork bomb
    r"curl.*\|\s*(ba)?sh",              # pipe URL to shell
    r"wget.*\|\s*(ba)?sh",             # pipe URL to shell
]

_DENYLIST_RE = [re.compile(p) for p in SAFETY_DENYLIST_PATTERNS]


def _matches_safety_denylist(command: str) -> bool:
    """Check if command matches any hardcoded safety denylist pattern."""
    return any(pat.search(command) for pat in _DENYLIST_RE)


def handle_pre_tool_use(input_data: dict, db_path: str | Path = DB_PATH) -> dict:
    """Handle PreToolUse hook: auto-allow commands with enough approval history.

    Returns:
        {"hookSpecificOutput": {"permissionDecision": "allow", ...}} if learned.
        {} if no opinion (fall through to Dippy or default behavior).
    """
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command or tool_name != "Bash":
        return {}

    if _matches_safety_denylist(command):
        return {}

    db = ApprovalDB(db_path)
    try:
        segments = extract_base_commands(command)
        is_compound = len(segments) > 1

        if is_compound:
            if db.should_auto_allow_compound(command):
                return {
                    "hookSpecificOutput": {
                        "permissionDecision": "allow",
                        "permissionDecisionReason":
                            f"Learned: all segments trusted ({', '.join(segments)})",
                    }
                }
        else:
            base = db._extract_base_command(command)
            if base and db.should_auto_allow(base):
                stats = db.get_stats(base)
                return {
                    "hookSpecificOutput": {
                        "permissionDecision": "allow",
                        "permissionDecisionReason":
                            f"Learned: {base} approved {stats['approve_count']}x",
                    }
                }

        return {}
    finally:
        db.close()


def handle_post_tool_use(input_data: dict, db_path: str | Path = DB_PATH):
    """Handle PostToolUse hook: command executed, so it was approved.

    Updates the most recent 'prompted' record for this command to 'allow'
    and bumps the approval stats. Also credits each segment of compound commands.
    """
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")
    working_dir = tool_input.get("cwd", input_data.get("cwd", ""))

    if not command or tool_name != "Bash":
        return

    db = ApprovalDB(db_path)
    try:
        prompted = db.execute(
            """SELECT id FROM approvals
               WHERE command = ? AND decision = 'prompted'
               ORDER BY timestamp DESC LIMIT 1""",
            (command,),
        ).fetchone()

        if prompted:
            db.execute(
                "UPDATE approvals SET decision = 'allow' WHERE id = ?",
                (prompted["id"],),
            )
            base = db._extract_base_command(command)
            if base:
                db.execute(
                    """INSERT INTO command_stats (base_command, approve_count, last_approved)
                       VALUES (?, 1, ?)
                       ON CONFLICT(base_command) DO UPDATE SET
                         approve_count = approve_count + 1,
                         last_approved = ?""",
                    (base, time.time(), time.time()),
                )
            base_commands = extract_base_commands(command)
            if len(base_commands) > 1:
                for seg_base in set(base_commands):
                    if seg_base != base:
                        db.execute(
                            """INSERT INTO command_stats (base_command, approve_count, last_approved)
                               VALUES (?, 1, ?)
                               ON CONFLICT(base_command) DO UPDATE SET
                                 approve_count = approve_count + 1,
                                 last_approved = ?""",
                            (seg_base, time.time(), time.time()),
                        )
        else:
            # No prompted record (auto-allowed or first time) — insert new
            db.record(tool_name, command, "allow", working_dir)

        db.conn.commit()
    finally:
        db.close()


# --- CLI Interface ---


def cli_stats(db_path: str | Path = DB_PATH) -> str:
    """Show approval statistics for all tracked commands."""
    db = ApprovalDB(db_path)
    try:
        rows = db.execute(
            """SELECT base_command, approve_count, deny_count, auto_allowed,
                      last_approved, last_denied
               FROM command_stats
               ORDER BY approve_count DESC"""
        ).fetchall()

        if not rows:
            return "No approval data recorded yet."

        lines = [f"{'Command':<20} {'Approved':>8} {'Denied':>7} {'Auto':>5} {'Status':<12}"]
        lines.append("-" * 60)
        for row in rows:
            status = "learned" if (
                row["approve_count"] >= LEARN_THRESHOLD and row["deny_count"] == 0
            ) else "blocked" if row["deny_count"] > 0 else "pending"
            lines.append(
                f"{row['base_command']:<20} {row['approve_count']:>8} "
                f"{row['deny_count']:>7} {row['auto_allowed']:>5} {status:<12}"
            )
        return "\n".join(lines)
    finally:
        db.close()


def cli_history(limit: int = 20, db_path: str | Path = DB_PATH) -> str:
    """Show recent approval history."""
    db = ApprovalDB(db_path)
    try:
        rows = db.execute(
            """SELECT timestamp, tool_name, command, decision, working_dir
               FROM approvals
               ORDER BY timestamp DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()

        if not rows:
            return "No history recorded yet."

        lines = []
        for row in rows:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["timestamp"]))
            cmd = row["command"][:60] + ("..." if len(row["command"]) > 60 else "")
            lines.append(f"{ts}  {row['decision']:<9} {cmd}")
        return "\n".join(lines)
    finally:
        db.close()


def cli_reset(base_command: str, db_path: str | Path = DB_PATH) -> str:
    """Reset stats for a specific command (removes learned status)."""
    db = ApprovalDB(db_path)
    try:
        db.execute("DELETE FROM command_stats WHERE base_command = ?", (base_command,))
        count = db.execute(
            "SELECT changes() as c"
        ).fetchone()["c"]
        db.conn.commit()
        return f"Reset stats for '{base_command}' ({count} row(s) removed)"
    finally:
        db.close()


# --- Main Entry Point ---


def main():
    """Entry point: hook mode (stdin JSON) or CLI mode (args)."""
    # CLI mode: approval_learner.py stats|history|reset
    # Only treat as CLI if it's a known command (not a test file path)
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd in ("stats", "history", "reset"):
            if cmd == "stats":
                print(cli_stats())
            elif cmd == "history":
                limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
                print(cli_history(limit))
            elif cmd == "reset":
                if len(sys.argv) < 3:
                    print("Usage: approval_learner.py reset <command>", file=sys.stderr)
                    sys.exit(1)
                print(cli_reset(sys.argv[2]))
            return

    # Hook mode: read JSON from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({}))
        return

    hook_event = input_data.get("hook_event_name", "")

    if hook_event == "PreToolUse":
        result = handle_pre_tool_use(input_data)
        print(json.dumps(result))
    elif hook_event == "PermissionRequest":
        handle_permission_request(input_data)
        print(json.dumps({}))
    elif hook_event == "PostToolUse":
        handle_post_tool_use(input_data)
        print(json.dumps({}))
    else:
        print(json.dumps({}))


if __name__ == "__main__":
    main()
