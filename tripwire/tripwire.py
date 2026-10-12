#!/usr/bin/env python3
"""Agent Tripwire: hard caps, loop killer, spend ledger, approval gates and a
watchdog for the Claude Code and OpenAI Codex CLIs, built on their hook systems.

Stdlib only. No telemetry: the only network call is the optional webhook you
configure yourself.
"""
import argparse, datetime as dt, fcntl, hashlib, json, os, re, sys, time, urllib.request
from contextlib import contextmanager

VERSION = "0.1.0"

DEFAULTS = {
    "caps": {"max_subagents": 20, "max_tokens": 5_000_000, "max_usd": 25.0, "max_tool_calls": 2000},
    "loop": {"enabled": True, "max_identical_in_window": 4, "window": 12},
    "daily_budget_usd": 50.0,
    # USD per 1M tokens. Estimates only: edit to match your plan/API prices.
    "prices": {
        "default": {"input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75},
        "opus": {"input": 15.0, "output": 75.0, "cache_read": 1.5, "cache_write": 18.75},
        "haiku": {"input": 1.0, "output": 5.0, "cache_read": 0.1, "cache_write": 1.25},
        "gpt-5": {"input": 1.25, "output": 10.0, "cache_read": 0.125, "cache_write": 0.0},
    },
    "approval": {
        "enabled": True,
        # "ask" = native prompt where supported (Claude Code); "deny" = block until
        # `tripwire approve <code>` is run (always used on Codex, which has no ask).
        "mode": "ask",
        "rules": [
            {"name": "rm -rf", "tool": "^(Bash|exec_command|shell)$", "input": r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR]|--recursive\s+--force|--force\s+--recursive)\b"},
            {"name": "force push", "tool": "^(Bash|exec_command|shell)$", "input": r"\bgit\s+push\b.*(\s--force\b|\s-f\b|\s--force-with-lease\b|\s\+\S+)"},
            {"name": "send", "tool": r"(?i)(^|__)(send|reply|forward|post|publish)[_a-z]*", "input": ""},
            {"name": "sign", "tool": r"(?i)(^|__)[a-z_]*sign[_a-z]*$", "input": ""},
            {"name": "delete", "tool": r"(?i)(^|__)(delete|trash|remove|destroy|drop)[_a-z]*", "input": ""},
            {"name": "submit", "tool": r"(?i)(^|__)(submit|merge)[_a-z]*", "input": ""},
            {"name": "purchase", "tool": r"(?i)(^|__)(purchase|buy|checkout|pay|order|place_order|charge)[_a-z]*", "input": ""},
            {"name": "shell send/delete", "tool": "^(Bash|exec_command|shell)$", "input": r"\b(gh\s+(repo|release)\s+delete|gh\s+pr\s+merge|sendmail|mail\s+-s|curl\b.*-X\s*(POST|DELETE)\b.*(api\.stripe|/send|/messages))"},
        ],
    },
    "watchdog": {"hung_minutes": 20},
    "webhook_url": "",
    "status_file": "",
}

AGENT_TOOLS = {"Task", "Agent", "spawn_agent"}
TODO_TOOLS = {"TodoWrite", "update_plan"}


def home():
    return os.path.expanduser(os.environ.get("TRIPWIRE_HOME", "~/.agent-tripwire"))


def deep_merge(a, b):
    out = dict(a)
    for k, v in b.items():
        out[k] = deep_merge(a[k], v) if isinstance(v, dict) and isinstance(a.get(k), dict) else v
    return out


def load_config():
    cfg = DEFAULTS
    for p in [os.path.join(home(), "config.json"), os.environ.get("TRIPWIRE_CONFIG", "")]:
        if p and os.path.exists(p):
            with open(p) as f:
                cfg = deep_merge(cfg, json.load(f))
    if os.environ.get("TRIPWIRE_WEBHOOK_URL"):
        cfg = deep_merge(cfg, {"webhook_url": os.environ["TRIPWIRE_WEBHOOK_URL"]})
    return cfg


def now():
    return time.time()


def today():
    return dt.date.today().isoformat()


def safe_id(s):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s or "unknown")[:120]


@contextmanager
def session_state(sid):
    d = os.path.join(home(), "sessions"); os.makedirs(d, exist_ok=True)
    path = os.path.join(d, safe_id(sid) + ".json")
    with open(path + ".lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        st = {}
        if os.path.exists(path):
            try:
                st = json.load(open(path))
            except Exception:
                st = {}
        st.setdefault("session_id", sid); st.setdefault("started", now())
        st.setdefault("subagents", 0); st.setdefault("tool_calls", 0); st.setdefault("tool_failures", 0)
        st.setdefault("tokens", 0); st.setdefault("usd", 0.0); st.setdefault("recent", [])
        st.setdefault("seen_msgs", []); st.setdefault("status", "running"); st.setdefault("notified", "")
        yield st
        tmp = path + ".tmp"
        json.dump(st, open(tmp, "w")); os.replace(tmp, path)


def ledger_append(rec):
    d = os.path.join(home(), "ledger"); os.makedirs(d, exist_ok=True)
    rec = dict(rec, ts=round(now(), 3), date=today())
    with open(os.path.join(d, today() + ".jsonl"), "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(rec) + "\n")


def read_ledger(day=None):
    d = os.path.join(home(), "ledger")
    files = [os.path.join(d, (day or today()) + ".jsonl")]
    out = []
    for p in files:
        if os.path.exists(p):
            for line in open(p):
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    return out


# ---------- usage from transcripts ----------

def price_for(model, prices):
    m = (model or "").lower()
    for k, v in prices.items():
        if k != "default" and k in m:
            return v
    return prices["default"]


def cost(u, p):
    return (u.get("input", 0) * p.get("input", 0) + u.get("output", 0) * p.get("output", 0)
            + u.get("cache_read", 0) * p.get("cache_read", 0) + u.get("cache_write", 0) * p.get("cache_write", 0)) / 1e6


def read_usage(transcript_path, cfg, cli, seen):
    """Returns (tokens_total_new, usd_new, seen_ids). Claude: sums per-message usage
    (deduped by message id). Codex: uses the latest cumulative token_count event."""
    if not transcript_path or not os.path.exists(transcript_path):
        return 0, 0.0, seen, None
    tok, usd, seen = 0, 0.0, list(seen)
    seen_set = set(seen)
    codex_total = None; model = None
    with open(transcript_path, errors="ignore") as f:
        for line in f:
            try:
                e = json.loads(line)
            except Exception:
                continue
            if not isinstance(e, dict):
                continue
            msg = e.get("message") if isinstance(e.get("message"), dict) else None
            if msg and isinstance(msg.get("usage"), dict):  # Claude Code
                mid = msg.get("id") or e.get("uuid")
                if mid in seen_set:
                    continue
                seen_set.add(mid); seen.append(mid)
                u = msg["usage"]
                uu = {"input": u.get("input_tokens", 0), "output": u.get("output_tokens", 0),
                      "cache_read": u.get("cache_read_input_tokens", 0), "cache_write": u.get("cache_creation_input_tokens", 0)}
                tok += sum(uu.values()); usd += cost(uu, price_for(msg.get("model"), cfg["prices"]))
            p = e.get("payload") if isinstance(e.get("payload"), dict) else None
            if p:  # Codex rollout
                if p.get("type") == "turn_context" or "model" in p:
                    model = p.get("model") or model
                if p.get("type") == "token_count" and isinstance(p.get("info"), dict):
                    t = p["info"].get("total_token_usage")
                    if isinstance(t, dict):
                        codex_total = t
    if codex_total is not None:
        cached = codex_total.get("cached_input_tokens", 0)
        uu = {"input": max(codex_total.get("input_tokens", 0) - cached, 0), "cache_read": cached,
              "output": codex_total.get("output_tokens", 0), "cache_write": 0}
        return sum(uu.values()), cost(uu, price_for(model, cfg["prices"])), seen[-5000:], "absolute"
    return tok, usd, seen[-5000:], "delta"


def update_usage(st, ev, cfg, cli):
    tok, usd, seen, kind = read_usage(ev.get("transcript_path"), cfg, cli, st["seen_msgs"])
    st["seen_msgs"] = seen
    if kind == "absolute":
        d_tok, d_usd = max(tok - st["tokens"], 0), max(usd - st["usd"], 0.0)
    else:
        d_tok, d_usd = tok, usd
    st["tokens"] += d_tok; st["usd"] = round(st["usd"] + d_usd, 6)
    return d_tok, d_usd


# ---------- notifications / status ----------

def notify(cfg, payload):
    url = cfg.get("webhook_url")
    payload = dict(payload, source="agent-tripwire", version=VERSION, ts=dt.datetime.utcnow().isoformat() + "Z")
    d = os.path.join(home(), "notices"); os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "notices.jsonl"), "a") as f:
        f.write(json.dumps(payload) + "\n")
    if not url:
        return False
    try:
        body = json.dumps({"text": payload.get("text", ""), **payload}).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()
        return True
    except Exception as e:
        print(f"tripwire: webhook failed: {e}", file=sys.stderr)
        return False


def write_status(st, cfg):
    d = os.path.join(home(), "status"); os.makedirs(d, exist_ok=True)
    elapsed = now() - st["started"]
    s = {"session_id": st["session_id"], "cli": st.get("cli"), "status": st["status"],
         "elapsed_s": round(elapsed), "tool_calls": st["tool_calls"], "tool_failures": st["tool_failures"],
         "subagents": st["subagents"], "tokens": st["tokens"], "usd": round(st["usd"], 4),
         "last_tool": st.get("last_tool"), "last_activity": st.get("last_activity")}
    todo = st.get("todo")
    if todo and todo.get("total"):
        s["progress"] = f"{todo['done']}/{todo['total']}"
        if todo["done"]:
            s["eta_s"] = round(elapsed / todo["done"] * (todo["total"] - todo["done"]))
    for p in [os.path.join(d, safe_id(st["session_id"]) + ".json"), cfg.get("status_file")]:
        if p:
            p = os.path.expanduser(p)
            os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
            json.dump(s, open(p + ".tmp", "w"), indent=2); os.replace(p + ".tmp", p)
    return s


def track_todos(st, tool, ti):
    items = None
    if tool == "TodoWrite":
        items = [(t.get("status") == "completed") for t in ti.get("todos", []) if isinstance(t, dict)]
    elif tool == "update_plan":
        items = [(t.get("status") == "completed") for t in ti.get("plan", []) if isinstance(t, dict)]
    if items is not None:
        st["todo"] = {"total": len(items), "done": sum(items)}


# ---------- decisions ----------

def call_hash(tool, ti):
    return hashlib.sha256((tool + "\0" + json.dumps(ti, sort_keys=True, default=str)).encode()).hexdigest()[:12]


def input_text(ti):
    if isinstance(ti, dict) and isinstance(ti.get("command"), str):
        return ti["command"]
    if isinstance(ti, dict) and isinstance(ti.get("command"), list):
        return " ".join(map(str, ti["command"]))
    return json.dumps(ti, default=str)


def match_rule(cfg, tool, ti):
    if not cfg["approval"].get("enabled"):
        return None
    text = input_text(ti)
    for r in cfg["approval"]["rules"]:
        if r.get("tool") and not re.search(r["tool"], tool):
            continue
        if r.get("input") and not re.search(r["input"], text):
            continue
        return r
    return None


def approvals_path():
    return os.path.join(home(), "approvals.json")


def consume_approval(h):
    p = approvals_path()
    if not os.path.exists(p):
        return False
    with open(p + ".lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        a = json.load(open(p))
        if h in a and a[h] > now():
            del a[h]; json.dump(a, open(p, "w")); return True
    return False


def pre_output(cli, decision, reason):
    """Return (stdout_json, exit_code) in the target CLI's documented format."""
    if decision == "ask" and cli == "codex":
        decision = "deny"  # Codex parses but does not support "ask" yet
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": reason}}, 0


def handle(event, ev, cli, cfg):
    sid = ev.get("session_id") or "unknown"
    out, code, notice = None, 0, None
    with session_state(sid) as st:
        st["cli"] = cli; st["last_activity"] = now()
        if st["status"] in ("done", "failed") and event in ("PreToolUse", "UserPromptSubmit", "PostToolUse"):
            st["status"] = "running"; st["notified"] = ""
        tool = ev.get("tool_name") or ""; ti = ev.get("tool_input") or {}
        agent = ev.get("agent_type") or ev.get("agent_id") or "main"
        caps = cfg["caps"]

        if event == "PreToolUse":
            h = call_hash(tool, ti)
            reason = None; decision = "deny"
            if st["usd"] >= caps["max_usd"]:
                reason = f"Agent Tripwire: session dollar cap reached (${st['usd']:.2f} >= ${caps['max_usd']}). Stop and report to the user."
            elif st["tokens"] >= caps["max_tokens"]:
                reason = f"Agent Tripwire: session token cap reached ({st['tokens']:,} >= {caps['max_tokens']:,}). Stop and report to the user."
            elif st["tool_calls"] >= caps["max_tool_calls"]:
                reason = f"Agent Tripwire: tool-call cap reached ({caps['max_tool_calls']}). Stop and report to the user."
            elif tool in AGENT_TOOLS and st["subagents"] >= caps["max_subagents"]:
                reason = f"Agent Tripwire: subagent cap reached ({st['subagents']}/{caps['max_subagents']}). Do not spawn more agents; finish with the ones you have."
            elif cfg["loop"]["enabled"]:
                win = st["recent"][-(cfg["loop"]["window"] - 1):] if cfg["loop"]["window"] > 1 else []
                if win.count(h) + 1 > cfg["loop"]["max_identical_in_window"]:
                    reason = (f"Agent Tripwire: loop detected, the identical {tool} call was made "
                              f"{win.count(h)} times in the last {len(win)} calls. Change approach or stop and report.")
            if reason is None:
                r = match_rule(cfg, tool, ti)
                if r and not consume_approval(h):
                    mode = cfg["approval"].get("mode", "ask")
                    if mode == "ask" and cli == "claude":
                        decision = "ask"
                        reason = f"Agent Tripwire: '{r['name']}' is irreversible and needs human approval."
                    else:
                        reason = (f"Agent Tripwire: '{r['name']}' is irreversible and needs human approval. "
                                  f"Ask the user to run `tripwire approve {h}` and then retry the same call unchanged.")
                    st.setdefault("pending", {})[h] = {"tool": tool, "rule": r["name"], "ts": now()}
            if reason:
                out, code = pre_output(cli, decision, reason)
                ledger_append({"session": sid, "cli": cli, "event": "blocked" if decision == "deny" else "ask",
                               "tool": tool, "agent": agent, "reason": reason})
                if decision == "deny" and "cap" in reason:
                    notice = {"kind": "cap", "text": reason}
            else:
                st["recent"] = (st["recent"] + [h])[-50:]
                st["tool_calls"] += 1
                if tool in AGENT_TOOLS:
                    st["subagents"] += 1
                st["last_tool"] = tool

        elif event in ("PostToolUse", "PostToolUseFailure"):
            d_tok, d_usd = update_usage(st, ev, cfg, cli)
            failed = event == "PostToolUseFailure"
            resp = ev.get("tool_response")
            if isinstance(resp, dict) and (resp.get("is_error") or resp.get("isError") or
                                           (isinstance(resp.get("exit_code"), int) and resp["exit_code"] != 0)):
                failed = True
            if failed:
                st["tool_failures"] += 1
            track_todos(st, tool, ti)
            ledger_append({"session": sid, "cli": cli, "event": "tool", "tool": tool, "agent": agent,
                           "tokens": d_tok, "usd": round(d_usd, 6), "failed": failed})
            spent = sum(r.get("usd", 0) for r in read_ledger())
            warn = budget_warning(spent, cfg["daily_budget_usd"])
            if warn and st.get("warned_day") != today():
                st["warned_day"] = today()
                out = {"systemMessage": warn}
                notice = {"kind": "budget", "text": warn}

        elif event in ("SubagentStart",):
            ledger_append({"session": sid, "cli": cli, "event": "subagent_start", "agent": agent})
        elif event in ("SubagentStop",):
            d_tok, d_usd = update_usage(st, ev, cfg, cli)
            ledger_append({"session": sid, "cli": cli, "event": "subagent_stop", "agent": agent, "tokens": d_tok, "usd": round(d_usd, 6)})
            if cli == "codex":
                out = {}
        elif event in ("Stop", "SessionEnd", "StopFailure"):
            d_tok, d_usd = update_usage(st, ev, cfg, cli)
            if d_tok:
                ledger_append({"session": sid, "cli": cli, "event": "turn", "tool": "(model)", "agent": agent,
                               "tokens": d_tok, "usd": round(d_usd, 6)})
            if event == "StopFailure":
                st["status"] = "failed"
                txt = f"FAILED: {cli} session {sid[:8]} stopped on an API error ({ev.get('error_type') or ev.get('matcher') or 'unknown'})."
            else:
                st["status"] = "done"
                fails = st["tool_failures"]
                txt = (f"DONE{' with ' + str(fails) + ' tool failure(s)' if fails else ''}: {cli} session {sid[:8]} "
                       f"after {st['tool_calls']} tool calls, {st['tokens']:,} tokens, ~${st['usd']:.2f}.")
            key = f"{event}:{st['tool_calls']}:{st['status']}"
            if st["notified"] != key:
                st["notified"] = key
                notice = {"kind": st["status"], "text": txt}
            if event == "Stop" and cli == "codex":
                out = {}
        elif event == "SessionStart":
            st["status"] = "running"
        write_status(st, cfg)
        snapshot = {k: st[k] for k in ("tool_calls", "tokens", "usd", "subagents", "status")}
    if notice:
        notify(cfg, dict(notice, session_id=sid, cli=cli, cwd=ev.get("cwd"), **snapshot))
    return out, code


def budget_warning(spent, budget, at=None):
    if not budget:
        return None
    t = at or dt.datetime.now()
    hours = t.hour + t.minute / 60 + t.second / 3600
    if spent >= budget:
        return f"Agent Tripwire: daily budget exhausted (${spent:.2f} of ${budget:.2f})."
    if hours >= 0.5 and spent > 0:
        rate = spent / hours
        projected = rate * 24
        if projected > budget:
            run_out = t + dt.timedelta(hours=(budget - spent) / rate)
            return (f"Agent Tripwire: at this pace you'll run out of today's ${budget:.2f} budget early, "
                    f"around {run_out.strftime('%H:%M')} (spent ${spent:.2f}, projected ${projected:.2f}).")
    return None


# ---------- CLI commands ----------

def cmd_summary(args, cfg):
    recs = read_ledger(args.date)
    if args.session:
        recs = [r for r in recs if r.get("session", "").startswith(args.session)]
    by_tool, by_agent, by_sess = {}, {}, {}
    blocked = 0
    for r in recs:
        if r.get("event") in ("blocked", "ask"):
            blocked += 1; continue
        for key, bucket in ((r.get("tool"), by_tool), (r.get("agent"), by_agent), (r.get("session"), by_sess)):
            if key is None:
                continue
            b = bucket.setdefault(key, [0, 0, 0.0]); b[0] += 1; b[1] += r.get("tokens", 0); b[2] += r.get("usd", 0)
    total = sum(v[2] for v in by_sess.values())
    if args.json:
        print(json.dumps({"date": args.date or today(), "usd": round(total, 4), "by_tool": by_tool, "by_agent": by_agent,
                          "by_session": by_sess, "blocked": blocked}, indent=2)); return 0
    print(f"Agent Tripwire spend for {args.date or today()}: ~${total:.2f} of ${cfg['daily_budget_usd']:.2f} daily budget; {blocked} blocked/asked calls")
    for title, b in (("By tool", by_tool), ("By agent", by_agent), ("By session", by_sess)):
        print(f"\n{title}:")
        for k, (n, t, u) in sorted(b.items(), key=lambda x: -x[1][2])[:15]:
            print(f"  {str(k)[:40]:40} {n:6} events {t:>12,} tok  ${u:8.4f}")
    if not args.date:
        w = budget_warning(total, cfg["daily_budget_usd"])
        if w:
            print("\n" + w)
    return 0


def cmd_approve(args, cfg):
    p = approvals_path(); os.makedirs(home(), exist_ok=True)
    with open(p + ".lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        a = json.load(open(p)) if os.path.exists(p) else {}
        a[args.code] = now() + args.minutes * 60
        json.dump(a, open(p, "w"))
    print(f"Approved {args.code} once (valid {args.minutes} min). Retry the same call.")
    return 0


def cmd_watchdog(args, cfg):
    hung = cfg["watchdog"]["hung_minutes"] * 60
    while True:
        d = os.path.join(home(), "sessions")
        for fn in (os.listdir(d) if os.path.isdir(d) else []):
            if not fn.endswith(".json"):
                continue
            sid = fn[:-5]
            st = json.load(open(os.path.join(d, fn)))
            idle = now() - st.get("last_activity", st.get("started", now()))
            if st.get("status") == "running" and idle > hung:
                with session_state(st["session_id"]) as s:
                    if s["status"] != "running":
                        continue
                    s["status"] = "failed"; s["notified"] = "hung"
                    write_status(s, cfg)
                notify(cfg, {"kind": "hung", "session_id": st["session_id"], "cli": st.get("cli"),
                             "text": f"FAILED (hung?): {st.get('cli')} session {sid[:8]} has been silent for {int(idle // 60)} min "
                                     f"(last tool: {st.get('last_tool')}). It may have stalled or died without reporting."})
        if args.once:
            return 0
        time.sleep(args.interval)


def cmd_status(args, cfg):
    d = os.path.join(home(), "status")
    for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        print(open(os.path.join(d, fn)).read())
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tripwire")
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hook"); h.add_argument("event"); h.add_argument("--cli", choices=["claude", "codex"], default="claude")
    s = sub.add_parser("summary"); s.add_argument("--date"); s.add_argument("--session"); s.add_argument("--json", action="store_true")
    a = sub.add_parser("approve"); a.add_argument("code"); a.add_argument("--minutes", type=int, default=10)
    w = sub.add_parser("watchdog"); w.add_argument("--once", action="store_true"); w.add_argument("--interval", type=int, default=60)
    sub.add_parser("status"); sub.add_parser("version")
    args = ap.parse_args(argv)
    cfg = load_config()
    if args.cmd == "hook":
        try:
            ev = json.loads(sys.stdin.read() or "{}")
        except Exception:
            ev = {}
        event = ev.get("hook_event_name") or args.event
        try:
            out, code = handle(event, ev, args.cli, cfg)
        except Exception as e:  # never break the agent because of our own bug
            print(f"tripwire internal error: {e}", file=sys.stderr)
            if event in ("Stop", "SubagentStop") and args.cli == "codex":
                print("{}")
            return 0
        if out is not None:
            print(json.dumps(out))
        return code
    return {"summary": cmd_summary, "approve": cmd_approve, "watchdog": cmd_watchdog, "status": cmd_status,
            "version": lambda a, c: print(VERSION) or 0}[args.cmd](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
