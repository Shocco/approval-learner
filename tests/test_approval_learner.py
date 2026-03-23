# tests/test_approval_learner.py
import tempfile
import os
import sys
import pytest
import json

# Add src dir to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from approval_learner import ApprovalDB, extract_base_commands


def test_db_creates_tables():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        db = ApprovalDB(db_path)
        tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = {row[0] for row in tables}
        assert "approvals" in table_names
        assert "command_stats" in table_names
        db.close()


def test_record_approval():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        db = ApprovalDB(db_path)
        db.record("Bash", "git status", "allow", "/home/user/project")
        db.record("Bash", "git status", "allow", "/home/user/project")
        stats = db.get_stats("git")
        assert stats["approve_count"] == 2
        assert stats["deny_count"] == 0
        db.close()


def test_record_denial_blocks_auto_allow():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        db = ApprovalDB(db_path)
        db.record("Bash", "rm -rf /tmp/foo", "allow", "/home/user")
        db.record("Bash", "rm -rf /tmp/foo", "allow", "/home/user")
        db.record("Bash", "rm -rf /tmp/bar", "deny", "/home/user")
        assert not db.should_auto_allow("rm")
        db.close()


def test_simple_command():
    assert extract_base_commands("git status") == ["git"]


def test_pipeline():
    assert extract_base_commands("cat file.txt | grep foo | wc -l") == ["cat", "grep", "wc"]


def test_and_chain():
    assert extract_base_commands("git add . && git commit -m 'msg'") == ["git", "git"]


def test_mixed_operators():
    assert extract_base_commands("ls -la | grep test && echo done; pwd") == ["ls", "grep", "echo", "pwd"]


def test_subshell():
    assert extract_base_commands("echo $(whoami)") == ["echo", "whoami"]


def test_single_word():
    assert extract_base_commands("pwd") == ["pwd"]


def test_compound_auto_allow_all_trusted():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        db = ApprovalDB(db_path)
        for _ in range(2):
            db.record("Bash", "cat file.txt", "allow", "/tmp")
            db.record("Bash", "grep foo bar.txt", "allow", "/tmp")
        assert db.should_auto_allow_compound("cat file.txt | grep foo") is True
        db.close()


def test_compound_auto_allow_one_unknown():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        db = ApprovalDB(db_path)
        for _ in range(2):
            db.record("Bash", "cat file.txt", "allow", "/tmp")
        # grep has never been seen
        assert db.should_auto_allow_compound("cat file.txt | grep foo") is False
        db.close()


def test_permission_request_logs_to_db():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        hook_input = {
            "hook_event_name": "PermissionRequest",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
        }
        from approval_learner import handle_permission_request
        handle_permission_request(hook_input, db_path=db_path)

        db = ApprovalDB(db_path)
        rows = db.execute("SELECT * FROM approvals").fetchall()
        assert len(rows) == 1
        assert rows[0]["command"] == "git status"
        assert rows[0]["tool_name"] == "Bash"
        db.close()


def test_pre_tool_use_allows_learned_command():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        db = ApprovalDB(db_path)
        # Pre-seed: git approved 3 times
        for _ in range(3):
            db.record("Bash", "git log --oneline", "allow", "/tmp")
        db.close()

        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git diff"},
        }
        from approval_learner import handle_pre_tool_use
        result = handle_pre_tool_use(hook_input, db_path=db_path)
        assert result["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_pre_tool_use_no_opinion_on_unknown():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "terraform destroy"},
        }
        from approval_learner import handle_pre_tool_use
        result = handle_pre_tool_use(hook_input, db_path=db_path)
        assert result == {}


def test_pre_tool_use_denylist_overrides_learned():
    """Even with many approvals, denylisted commands never auto-allow."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        db = ApprovalDB(db_path)
        for _ in range(100):
            db.record("Bash", "rm -rf /tmp/safe", "allow", "/tmp")
        db.close()

        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        }
        from approval_learner import handle_pre_tool_use
        result = handle_pre_tool_use(hook_input, db_path=db_path)
        assert result == {}


def test_pre_tool_use_allows_compound_when_all_trusted():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        db = ApprovalDB(db_path)
        for _ in range(2):
            db.record("Bash", "cat file.txt", "allow", "/tmp")
            db.record("Bash", "grep -r foo .", "allow", "/tmp")
            db.record("Bash", "wc -l output.txt", "allow", "/tmp")
        db.close()

        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat README.md | grep TODO | wc -l"},
        }
        from approval_learner import handle_pre_tool_use
        result = handle_pre_tool_use(hook_input, db_path=db_path)
        assert result["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_post_tool_use_confirms_approval():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        db = ApprovalDB(db_path)
        db.record("Bash", "docker ps", "prompted", "/tmp")
        db.close()

        hook_input = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "docker ps"},
        }
        from approval_learner import handle_post_tool_use
        handle_post_tool_use(hook_input, db_path=db_path)

        db = ApprovalDB(db_path)
        rows = db.execute(
            "SELECT decision FROM approvals WHERE command = ?", ("docker ps",)
        ).fetchall()
        decisions = [r["decision"] for r in rows]
        assert "allow" in decisions
        stats = db.get_stats("docker")
        assert stats["approve_count"] == 1
        db.close()


def test_main_routes_pre_tool_use(monkeypatch):
    import io
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")
        db = ApprovalDB(db_path)
        for _ in range(3):
            db.record("Bash", "ls -la", "allow", "/tmp")
        db.close()

        hook_input = json.dumps({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        })
        monkeypatch.setattr("sys.stdin", io.StringIO(hook_input))
        monkeypatch.setenv("APPROVAL_STATE_DIR", tmp)

        import importlib
        import approval_learner
        importlib.reload(approval_learner)

        captured = io.StringIO()
        monkeypatch.setattr("sys.stdout", captured)
        approval_learner.main()
        output = json.loads(captured.getvalue())
        assert output["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_cli_stats(tmp_path):
    db_path = tmp_path / "approvals.db"
    db = ApprovalDB(str(db_path))
    for _ in range(5):
        db.record("Bash", "git status", "allow", "/tmp")
    db.record("Bash", "rm -rf /", "deny", "/tmp")
    db.close()

    from approval_learner import cli_stats
    output = cli_stats(db_path=str(db_path))
    assert "git" in output
    assert "5" in output  # approve count
    assert "rm" in output


def test_full_learning_cycle():
    """Simulate: user approves 'git status' twice, then it auto-allows."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "approvals.db")

        # Import handlers at function scope
        from approval_learner import handle_permission_request, handle_post_tool_use, handle_pre_tool_use

        # 1. First time: PermissionRequest fires (user sees prompt)
        handle_permission_request(
            {"hook_event_name": "PermissionRequest", "tool_name": "Bash",
             "tool_input": {"command": "git status"}},
            db_path=db_path,
        )

        # 2. User approves -> PostToolUse fires
        handle_post_tool_use(
            {"hook_event_name": "PostToolUse", "tool_name": "Bash",
             "tool_input": {"command": "git status"}},
            db_path=db_path,
        )

        # 3. Not yet learned (only 1 approval)
        result = handle_pre_tool_use(
            {"hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": "git diff"}},
            db_path=db_path,
        )
        assert result == {}  # No opinion yet

        # 4. Second approval cycle
        handle_permission_request(
            {"hook_event_name": "PermissionRequest", "tool_name": "Bash",
             "tool_input": {"command": "git log"}},
            db_path=db_path,
        )
        handle_post_tool_use(
            {"hook_event_name": "PostToolUse", "tool_name": "Bash",
             "tool_input": {"command": "git log"}},
            db_path=db_path,
        )

        # 5. Now git is learned (2 approvals, 0 denials)
        result = handle_pre_tool_use(
            {"hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": "git stash"}},
            db_path=db_path,
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "allow"

        # 6. Verify pipeline with learned commands
        for cmd in ["cat README.md", "grep TODO README.md"]:
            handle_post_tool_use(
                {"hook_event_name": "PostToolUse", "tool_name": "Bash",
                 "tool_input": {"command": cmd}},
                db_path=db_path,
            )
            handle_post_tool_use(
                {"hook_event_name": "PostToolUse", "tool_name": "Bash",
                 "tool_input": {"command": cmd}},
                db_path=db_path,
            )

        result = handle_pre_tool_use(
            {"hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": "cat file.txt | grep pattern"}},
            db_path=db_path,
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "allow"
