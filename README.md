# Agent Tripwire

**Hard caps, a loop killer, a spend ledger, approval gates and a done/failed watchdog for the Claude Code CLI and the OpenAI Codex CLI.** Free, MIT, one Python file, stdlib only, no telemetry.

Agent Tripwire plugs into each CLI's own documented hook system ([Claude Code hooks](https://code.claude.com/docs/en/hooks), [Codex hooks](https://developers.openai.com/codex/hooks)). It does not wrap, proxy or patch either CLI.

## Why this exists (the evidence)

- **826 agents, ~$78,000, no report.** *"My OpenAI CODEX account went rogue and from a simple request took the autonomous decision to launch 826 parallel agents / threads without any authorization… consuming a total of roughly USD 78,000 and deleting all records of what was done."* ([HN 49861047](https://news.ycombinator.com/item?id=49861047))
- **An agent signed a contract on its own.** *"It downloaded the PDF contract. Found a saved signature PNG on my computer, placed it at the right spot within the contract and prepared to send it when I intervened."* ([HN 49798257](https://news.ycombinator.com/item?id=49798257))
- **Usage burn nobody can explain, and silent failures.** Replies to [this X thread](https://x.com/elonmusk/status/2109682666140553434) (Oct 12, 2026, 600+ replies), for example:
  - *"We need better ways to understand how we're burning our usage! Some of us burn it all in 4 days… None of us understand why."* ([@ArbitraryFlux](https://x.com/ArbitraryFlux/status/2109759902575202726))
  - *"…it eagerly jumps in, keeps excitement high only to go completely silent in couple of hours leaving it to you to discover that it ran out of steam/tokens."* ([@rosiwan07](https://x.com/rosiwan07/status/2109777202632134695))
  - *"A real-time usage meter the bot itself can read (and throttle against) would help."* ([@STate84182](https://x.com/STate84182/status/2109768306790142313))
  - *"Can we get an option to limit tok/s to whatever would max out the weekly allotment? I'm tired of running out in 1 day."* ([@ubermetroid](https://x.com/ubermetroid/status/2109755211392909643))
  - The thread itself starts from a coordinator bot that, by default, *"reads everything they do constantly"* when spinning up lots of agents, and the suggestion that it *"should warn when spiking usage."* ([@EMostaque](https://x.com/EMostaque/status/2109680284257911002))

Those threads are about several products. Tripwire covers the two CLIs that expose hooks.

## What it does

| # | Feature | How |
|---|---|---|
| 1 | **Hard caps per session**: subagents, tokens, dollars, tool calls | `PreToolUse` denies the next call once a cap is hit. Subagent spawns (`Agent`/`Task` on Claude Code, `spawn_agent` on Codex) are counted and denied past the cap |
| 2 | **Loop killer** | The same tool and the same input more than N times in the last W calls gets denied, with a message telling the agent to change approach |
| 3 | **Spend ledger + daily budget** | JSONL ledger per day, `tripwire summary` with per-tool / per-agent / per-session breakdowns, and a "you'll run out early" warning when today's pace projects past your budget |
| 4 | **Human approval before irreversible actions** | Regex rules for send, sign, delete, submit, purchase/order, `git push --force`, `rm -rf`. Claude Code shows its native approval prompt. Codex blocks the call until you run `tripwire approve <code>` |
| 5 | **Watchdog** | Always sends a DONE / FAILED notice (to a webhook if you set one, and always to a local `notices.jsonl`): when a turn stops, when the session ends, on API failures (Claude Code), and from `tripwire watchdog` when a run goes silent for N minutes. DONE notices include the tool-failure count, so silent failures are visible |
| 6 | **Progress / ETA status file** (optional) | JSON with elapsed time, tool calls, tokens, $, and progress/ETA taken from the agent's own todo list (`TodoWrite` / `update_plan`) |

## Per-CLI support (honest version)

Checked against both CLIs' official hook docs on 2026-10-12.

| Capability | Claude Code | Codex CLI |
|---|---|---|
| Block a tool call (`PreToolUse` deny) | ✅ | ✅ Covers shell, `apply_patch`, MCP and local function tools. **Not** hosted tools like web search. OpenAI calls hooks "a useful guardrail, not a complete enforcement boundary" |
| Native "ask the human" decision | ✅ `permissionDecision: "ask"` | ❌ `ask` is parsed but not supported yet, so Tripwire **denies** and prints a one-time `tripwire approve <code>` |
| Cap subagents | ✅ Blocks the `Agent`/`Task` tool | ✅ Blocks `spawn_agent` (matches `Agent`). `SubagentStart` can't block on either CLI, so we only log it |
| Token / $ figures | Estimated from `message.usage` in the transcript × your price table | Read from the cumulative `token_count` events in the rollout × your price table |
| API-failure notice | ✅ `StopFailure` | ⚠️ No equivalent event. Use the watchdog |
| Tool-failure count | ✅ `PostToolUseFailure` | ⚠️ Taken from `tool_response` when it shows an error or non-zero exit |
| Done notice | ✅ `Stop` + `SessionEnd` | ✅ `Stop` + `SessionEnd` (SessionEnd has a 1–3 s budget; the webhook timeout is 5 s, so for long webhooks the `Stop` notice is the one you can count on) |
| Hook trust | Runs once it's in settings | You must trust the hooks in `/hooks` before they run |

**Limits you should know about:**

- Dollar figures are **estimates**. Transcript formats are not a stable interface on either CLI, and the default price table is a guess, so edit `prices` in your config. Subscription plans don't bill per token, so treat $ there as "API-equivalent burn".
- Caps take effect at the **next tool call**. A single huge model response can overshoot.
- Usage is attributed to the tool call that came before it. That is a heuristic.
- Hooks that time out or crash **fail open** on both CLIs. On Claude Code ≥ 2.1.295 you can add `"onFailure": "block"` to the PreToolUse entry to fail closed.
- The watchdog is a separate process (`tripwire watchdog`). Run it under cron, launchd or systemd, or in a tmux pane. Hooks can't notice a CLI that died silently.

## Install

Needs Python 3.8+ (macOS/Linux; Windows untested because it uses `fcntl`).

```bash
git clone https://github.com/guymcmaster/agent-tripwire
cd agent-tripwire && ./install/install.sh
alias tripwire='python3 ~/.agent-tripwire/bin/tripwire.py'
```

The installer only copies files into `~/.agent-tripwire/`. **It never edits your CLI settings.** Wire the hooks up yourself:

**Claude Code:** merge [`examples/claude-settings.json`](examples/claude-settings.json) into the `"hooks"` key of `~/.claude/settings.json` (or `.claude/settings.json` in a project). Check with `/hooks`.

**Codex CLI:** copy [`examples/codex-hooks.json`](examples/codex-hooks.json) to `~/.codex/hooks.json` (or merge it with yours), start Codex, open `/hooks` and **trust** the Tripwire hooks.

Each entry looks like this:

```json
{"matcher": "", "hooks": [{"type": "command", "command": "python3 ~/.agent-tripwire/bin/tripwire.py hook PreToolUse --cli claude", "timeout": 10}]}
```

## Configure

`~/.agent-tripwire/config.json` (or point `TRIPWIRE_CONFIG` at a file). It is merged over the defaults; the full default file is in [`examples/config.json`](examples/config.json).

```json
{
  "caps": {"max_subagents": 10, "max_tokens": 3000000, "max_usd": 15, "max_tool_calls": 1500},
  "loop": {"enabled": true, "max_identical_in_window": 4, "window": 12},
  "daily_budget_usd": 40,
  "approval": {"mode": "ask"},
  "watchdog": {"hung_minutes": 20},
  "webhook_url": "https://hooks.slack.com/services/XXX/YYY/ZZZ",
  "status_file": "~/agent-status.json"
}
```

- `approval.rules` is a list of `{"name", "tool", "input"}` regexes. `tool` is matched against the tool name (e.g. `mcp__gmail__send_message`) and `input` against the shell command or the JSON tool input. If you set `rules`, it **replaces** the default list.
- `webhook_url` can also come from the `TRIPWIRE_WEBHOOK_URL` env var. The body is JSON with a `text` field, so Slack and Discord-compatible incoming webhooks, ntfy, n8n and Zapier all accept it.
- State lives in `~/.agent-tripwire/` (override with `TRIPWIRE_HOME`).

## Examples

```console
$ tripwire summary
Agent Tripwire spend for 2026-10-12: ~$18.40 of $40.00 daily budget; 3 blocked/asked calls

By tool:
  Bash                                         212 events    2,104,331 tok  $  9.1200
  (model)                                       40 events      801,220 tok  $  4.0100
  Agent                                         11 events      640,002 tok  $  3.2000
By agent:
  main                                         231 events    2,950,000 tok  $ 14.2000
  Explore                                       32 events      595,553 tok  $  4.2000
...
Agent Tripwire: at this pace you'll run out of today's $40.00 budget early, around 17:10 (spent $18.40, projected $62.00).
```

What the agent sees when it trips a wire:

```text
Agent Tripwire: subagent cap reached (10/10). Do not spawn more agents; finish with the ones you have.
Agent Tripwire: loop detected, the identical Bash call was made 4 times in the last 11 calls. Change approach or stop and report.
Agent Tripwire: 'rm -rf' is irreversible and needs human approval. Ask the user to run `tripwire approve 3f9a1c0b2d4e` and then retry the same call unchanged.   (Codex)
```

Other commands:

```bash
tripwire summary --json            # machine-readable
tripwire summary --date 2026-10-11 --session abc123
tripwire approve 3f9a1c0b2d4e      # one-time approval, valid 10 min (Codex / deny mode)
tripwire watchdog                  # loop forever, check every 60 s; --once for cron
tripwire status                    # print every session's status JSON
```

Webhook payload:

```json
{"text": "DONE with 2 tool failure(s): claude session 1a2b3c4d after 87 tool calls, 1,204,113 tokens, ~$6.12.",
 "kind": "done", "session_id": "...", "cli": "claude", "cwd": "...", "tool_calls": 87, "tokens": 1204113, "usd": 6.12,
 "source": "agent-tripwire", "version": "0.1.0", "ts": "2026-10-12T23:40:00Z"}
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

21 tests run the real script as a subprocess, feeding it simulated hook payloads for both CLIs: caps (subagents, tokens, $, tool calls), Claude transcript and Codex rollout usage parsing (no double counting), the loop killer, approval rules (ask on Claude, deny + one-time approve on Codex, and no false positives on safe calls), webhook DONE/FAILED/hung notices against a local HTTP sink, a dead webhook that must not break the hook, ledger breakdowns, budget-pace math, status/ETA from `TodoWrite` and `update_plan`, garbage input, and 12 parallel hooks with no lost updates.

## Privacy

No telemetry, no analytics, no calls home. Everything stays in `~/.agent-tripwire/`. The only network request is the webhook you configure, which gets the summary shown above (no prompts, no tool inputs).

## More from GM Labs

- **[GM Labs on Apify](https://apify.com/appetizing_horsefly)**: ready-to-run data Actors (public records, business filings, licenses, site monitors), usable as MCP tools.
- **[gm-labs-data-plugin](https://github.com/guymcmaster/gm-labs-data-plugin)**: plug those data sources straight into your agent.

## License

MIT © 2026 GM Labs (Guy McAllister)
