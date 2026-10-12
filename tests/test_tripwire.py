import json, os, subprocess, sys, tempfile, threading, unittest, datetime as dt
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "tripwire", "tripwire.py")
sys.path.insert(0, os.path.join(ROOT, "tripwire"))
import tripwire as tw  # noqa


class Hook:
    def __init__(self, cfg=None):
        self.home = tempfile.mkdtemp()
        self.cfg_path = os.path.join(self.home, "config.json")
        open(self.cfg_path, "w").write(json.dumps(cfg or {}))

    def run(self, event, payload, cli="claude", args=None):
        env = dict(os.environ, TRIPWIRE_HOME=self.home)
        env.pop("TRIPWIRE_WEBHOOK_URL", None)
        payload = dict({"session_id": "s1", "cwd": "/tmp", "hook_event_name": event}, **payload)
        p = subprocess.run([sys.executable, SCRIPT] + (args or ["hook", event, "--cli", cli]),
                           input=json.dumps(payload), capture_output=True, text=True, env=env)
        out = json.loads(p.stdout) if p.stdout.strip().startswith("{") else None
        return p.returncode, out, p

    def cli(self, *args):
        env = dict(os.environ, TRIPWIRE_HOME=self.home)
        return subprocess.run([sys.executable, SCRIPT] + list(args), capture_output=True, text=True, env=env)


def decision(out):
    return (out or {}).get("hookSpecificOutput", {}).get("permissionDecision")


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


class TestCaps(unittest.TestCase):
    def test_subagent_cap_claude_and_codex(self):
        for cli, tool in (("claude", "Agent"), ("claude", "Task"), ("codex", "spawn_agent")):
            h = Hook({"caps": {"max_subagents": 2}, "loop": {"enabled": False}})
            for i in range(2):
                _, out, _ = h.run("PreToolUse", {"tool_name": tool, "tool_input": {"prompt": f"job {i}"}}, cli)
                self.assertIsNone(out)
            _, out, _ = h.run("PreToolUse", {"tool_name": tool, "tool_input": {"prompt": "job 3"}}, cli)
            self.assertEqual(decision(out), "deny")
            self.assertIn("subagent cap", out["hookSpecificOutput"]["permissionDecisionReason"])

    def _claude_transcript(self, d, n, model="claude-sonnet-4-5"):
        p = os.path.join(d, "t.jsonl")
        with open(p, "a") as f:
            for i in range(n):
                f.write(json.dumps({"type": "assistant", "message": {"id": f"m{os.path.getsize(p)}-{i}", "model": model,
                        "usage": {"input_tokens": 100000, "output_tokens": 100000}}}) + "\n")
        return p

    def test_token_and_dollar_cap_from_claude_transcript(self):
        h = Hook({"caps": {"max_tokens": 10_000_000, "max_usd": 3.0}})
        t = self._claude_transcript(h.home, 2)  # 2 msgs x (0.1M in @3 + 0.1M out @15) = $3.60
        h.run("PostToolUse", dict(bash("ls"), transcript_path=t))
        st = json.load(open(os.path.join(h.home, "sessions", "s1.json")))
        self.assertEqual(st["tokens"], 400000)
        self.assertAlmostEqual(st["usd"], 3.6, places=4)
        # re-reading the same transcript must not double count
        h.run("PostToolUse", dict(bash("ls"), transcript_path=t))
        st = json.load(open(os.path.join(h.home, "sessions", "s1.json")))
        self.assertEqual(st["tokens"], 400000)
        _, out, _ = h.run("PreToolUse", bash("echo hi"))
        self.assertEqual(decision(out), "deny")
        self.assertIn("dollar cap", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_token_cap_from_codex_rollout(self):
        h = Hook({"caps": {"max_tokens": 1000, "max_usd": 1000}})
        t = os.path.join(h.home, "rollout.jsonl")
        with open(t, "w") as f:
            f.write(json.dumps({"type": "turn_context", "payload": {"model": "gpt-5-codex"}}) + "\n")
            f.write(json.dumps({"type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 800, "cached_input_tokens": 200, "output_tokens": 300}}}}) + "\n")
        h.run("PostToolUse", dict(bash("ls"), transcript_path=t, tool_response="ok"), "codex")
        h.run("PostToolUse", dict(bash("ls"), transcript_path=t, tool_response="ok"), "codex")  # cumulative, no double count
        st = json.load(open(os.path.join(h.home, "sessions", "s1.json")))
        self.assertEqual(st["tokens"], 1100)
        _, out, _ = h.run("PreToolUse", bash("ls -la"), "codex")
        self.assertEqual(decision(out), "deny")

    def test_tool_call_cap(self):
        h = Hook({"caps": {"max_tool_calls": 3}, "loop": {"enabled": False}})
        for i in range(3):
            self.assertIsNone(h.run("PreToolUse", bash(f"echo {i}"))[1])
        self.assertEqual(decision(h.run("PreToolUse", bash("echo 4"))[1]), "deny")


class TestLoop(unittest.TestCase):
    def test_identical_calls_killed(self):
        h = Hook({"loop": {"max_identical_in_window": 3, "window": 10}})
        for _ in range(3):
            self.assertIsNone(h.run("PreToolUse", bash("curl https://example.com/status"))[1])
        _, out, _ = h.run("PreToolUse", bash("curl https://example.com/status"))
        self.assertEqual(decision(out), "deny")
        self.assertIn("loop detected", out["hookSpecificOutput"]["permissionDecisionReason"])
        # a different call still goes through
        self.assertIsNone(h.run("PreToolUse", bash("cat log.txt"))[1])

    def test_varied_calls_not_flagged(self):
        h = Hook({"loop": {"max_identical_in_window": 3, "window": 10}})
        for i in range(20):
            self.assertIsNone(h.run("PreToolUse", bash(f"pytest -k case{i}"))[1])


class TestApproval(unittest.TestCase):
    def test_claude_asks_for_irreversible(self):
        h = Hook()
        for p in (bash("rm -rf build/"), bash("git push --force origin main"), bash("git push origin +main"),
                  {"tool_name": "mcp__gmail__send_message", "tool_input": {"to": "a@b.c"}},
                  {"tool_name": "mcp__docusign__sign_envelope", "tool_input": {}},
                  {"tool_name": "mcp__drive__delete_file", "tool_input": {"id": "1"}},
                  {"tool_name": "mcp__forms__submit_form", "tool_input": {}},
                  {"tool_name": "mcp__shop__place_order", "tool_input": {"sku": "x"}}):
            _, out, _ = h.run("PreToolUse", p)
            self.assertEqual(decision(out), "ask", p)

    def test_safe_calls_pass(self):
        h = Hook()
        for p in (bash("rm file.txt"), bash("git push origin main"), bash("ls -rf"),
                  {"tool_name": "Read", "tool_input": {"file_path": "/x/delete_me.txt"}},
                  {"tool_name": "mcp__gmail__search", "tool_input": {"q": "send"}}):
            self.assertIsNone(h.run("PreToolUse", p)[1], p)

    def test_codex_denies_then_approve_once(self):
        h = Hook()
        p = bash("rm -rf dist")
        _, out, _ = h.run("PreToolUse", p, "codex")
        self.assertEqual(decision(out), "deny")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        code = reason.split("tripwire approve ")[1].split("`")[0]
        self.assertEqual(h.cli("approve", code).returncode, 0)
        self.assertIsNone(h.run("PreToolUse", p, "codex")[1])           # approved once
        self.assertEqual(decision(h.run("PreToolUse", p, "codex")[1]), "deny")  # consumed

    def test_deny_mode_on_claude(self):
        h = Hook({"approval": {"mode": "deny"}})
        self.assertEqual(decision(h.run("PreToolUse", bash("rm -rf /tmp/x"))[1]), "deny")


class WebhookSink(BaseHTTPRequestHandler):
    got = []
    def do_POST(self):
        WebhookSink.got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass


class TestWatchdogAndNotices(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), WebhookSink)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/hook"

    def setUp(self):
        WebhookSink.got.clear()

    def test_done_notice_on_stop_with_failures(self):
        h = Hook({"webhook_url": self.url})
        h.run("PreToolUse", bash("make"))
        h.run("PostToolUseFailure", dict(bash("make"), error="exit 2"))
        rc, out, _ = h.run("Stop", {"stop_hook_active": False})
        self.assertEqual(rc, 0)
        self.assertEqual(len(WebhookSink.got), 1)
        self.assertTrue(WebhookSink.got[0]["text"].startswith("DONE with 1 tool failure"))
        h.run("SessionEnd", {"reason": "other"})  # distinct event -> one more notice, never silent
        self.assertEqual(len(WebhookSink.got), 2)

    def test_codex_stop_prints_json(self):
        h = Hook({"webhook_url": self.url})
        rc, out, p = h.run("Stop", {"turn_id": "t1", "stop_hook_active": False}, "codex")
        self.assertEqual(out, {})
        self.assertEqual(WebhookSink.got[0]["kind"], "done")

    def test_failed_notice_on_stopfailure(self):
        h = Hook({"webhook_url": self.url})
        h.run("StopFailure", {"error_type": "rate_limit"})
        self.assertTrue(WebhookSink.got[0]["text"].startswith("FAILED"))

    def test_hung_run_detected(self):
        h = Hook({"webhook_url": self.url, "watchdog": {"hung_minutes": 0}})
        h.run("PreToolUse", bash("sleep 9999"))
        import time; time.sleep(0.05)
        self.assertEqual(h.cli("watchdog", "--once").returncode, 0)
        self.assertEqual(WebhookSink.got[0]["kind"], "hung")
        h.cli("watchdog", "--once")
        self.assertEqual(len(WebhookSink.got), 1)  # notified once

    def test_dead_webhook_never_breaks_hook(self):
        h = Hook({"webhook_url": "http://127.0.0.1:9/nope"})
        rc, _, _ = h.run("Stop", {})
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(os.path.join(h.home, "notices", "notices.jsonl")))


class TestLedgerStatus(unittest.TestCase):
    def test_summary_breakdown(self):
        h = Hook()
        t = os.path.join(h.home, "t.jsonl")
        open(t, "w").write(json.dumps({"message": {"id": "a", "model": "sonnet", "usage": {"input_tokens": 1000, "output_tokens": 1000}}}) + "\n")
        h.run("PostToolUse", dict(bash("ls"), transcript_path=t))
        with open(t, "a") as f:
            f.write(json.dumps({"message": {"id": "b", "model": "sonnet", "usage": {"input_tokens": 5000, "output_tokens": 0}}}) + "\n")
        h.run("PostToolUse", {"tool_name": "Grep", "tool_input": {"pattern": "x"}, "transcript_path": t,
                              "agent_type": "Explore", "agent_id": "ag1"})
        s = json.loads(h.cli("summary", "--json").stdout)
        self.assertEqual(s["by_tool"]["Bash"][1], 2000)
        self.assertEqual(s["by_tool"]["Grep"][1], 5000)
        self.assertIn("Explore", s["by_agent"])
        self.assertIn("By tool", h.cli("summary").stdout)

    def test_budget_warning_math(self):
        noon = dt.datetime(2026, 10, 12, 12, 0)
        self.assertIsNone(tw.budget_warning(10, 50, noon))          # pace $20/day
        w = tw.budget_warning(30, 50, noon)                          # pace $60/day
        self.assertIn("run out", w); self.assertIn("20:00", w)
        self.assertIn("exhausted", tw.budget_warning(51, 50, noon))

    def test_status_file_with_eta(self):
        h = Hook({"status_file": os.path.join(tempfile.mkdtemp(), "progress.json")})
        h.run("PostToolUse", {"tool_name": "TodoWrite", "tool_input": {"todos": [
            {"content": "a", "status": "completed"}, {"content": "b", "status": "in_progress"},
            {"content": "c", "status": "pending"}, {"content": "d", "status": "pending"}]}})
        cfg = json.load(open(h.cfg_path))
        s = json.load(open(cfg["status_file"]))
        self.assertEqual(s["progress"], "1/4"); self.assertIn("eta_s", s)

    def test_codex_update_plan_progress(self):
        h = Hook()
        h.run("PostToolUse", {"tool_name": "update_plan", "tool_input": {"plan": [
            {"step": "a", "status": "completed"}, {"step": "b", "status": "completed"}, {"step": "c", "status": "pending"}]},
            "tool_response": "ok"}, "codex")
        s = json.load(open(os.path.join(h.home, "status", "s1.json")))
        self.assertEqual(s["progress"], "2/3")

    def test_garbage_input_is_safe(self):
        h = Hook()
        env = dict(os.environ, TRIPWIRE_HOME=h.home)
        p = subprocess.run([sys.executable, SCRIPT, "hook", "PreToolUse"], input="not json", capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0)

    def test_parallel_hooks_no_lost_updates(self):
        h = Hook({"loop": {"enabled": False}})
        ts = [threading.Thread(target=h.run, args=("PreToolUse", bash(f"echo {i}"))) for i in range(12)]
        [t.start() for t in ts]; [t.join() for t in ts]
        st = json.load(open(os.path.join(h.home, "sessions", "s1.json")))
        self.assertEqual(st["tool_calls"], 12)


if __name__ == "__main__":
    unittest.main()
