# Final review guide — CodeAudit (100 %)

## 1. Brief → what we built

| The brief asks for | Where it is | How to show it |
|---|---|---|
| Multi-agent CLI **or** local web app | Both: `python -m codeaudit audit …` and `python -m codeaudit serve` | Run the CLI, then open the web UI |
| Ingests a GitHub repository | `ingest.py` (local folder or URL → shallow clone) | `audit https://github.com/pallets/itsdangerous` |
| Constructs a Dependency Graph | `graph.py`: symbol graph + module graph, PageRank, blast radius | Report → "Module dependency graph" (red = cycle) |
| Static analysis combined with LLMs | Rules find candidates, the 4 agents judge, explain and fix | Report → open any finding |
| Architectural smells | Import cycles, god modules, hub modules, god classes | F005 cycle in shopkart |
| Security vulnerabilities | 8 CWE-mapped sinks + taint path from user input | F002 SQL injection, path `main → handle → get_user` |
| Dead code | Reachability from entry points; transitive dead code; unused modules | `_to_xml` (only used by dead code), `legacy.py` |
| Refactoring PRs | Refactorer + Validator → `pr.py` branches / GitHub PRs | Web UI "Create PR branch" or `pr --sandbox` |
| (Our problem) AI lacks repo context | `context.py` builds a small, graph-based context pack per finding | `context examples/shopkart F002`: ~360 tokens vs ~2,300 for the whole repo |

## 2. Tonight (30–40 min, on the laptop you will present from)

```powershell
cd codeaudit
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q                                  # must say: 45 passed
```

Then pick your AI and run the demo once **with it**, so the answers are cached and tomorrow's run is
instant and works without internet:

```powershell
$env:ANTHROPIC_API_KEY="sk-ant-..."                  # or GEMINI_API_KEY / OPENAI_API_KEY / GROQ_API_KEY
python -m codeaudit providers                        # check it shows ✓
python -m codeaudit audit examples/shopkart --run-tests --refactor-k 12 --labels examples/shopkart_labels.csv --open
python -m codeaudit benchmark examples/shopkart examples/shopkart_labels.csv --provider anthropic
```

- Any OpenAI-compatible service works: `--provider openai --base-url https://<host>/v1 --model <name>`.
- Free local option: install Ollama, run `ollama pull qwen2.5-coder:7b`, then use `--provider ollama`.
- **Write down the benchmark table.** If the AI triage keeps `password_key` as a real issue, recall goes
  up compared with offline. That's the clearest proof the LLM adds value.
- Keep `audit_out/report.html` open in a browser tab as a backup.
- **Accept really edits files.** For the web-UI part use a copy: `xcopy /E /I examples\shopkart demo_copy`
  (macOS/Linux: `cp -r examples/shopkart demo_copy`) and type `demo_copy` in the form. Delete and re-copy
  it to reset.
- Zoom the terminal font (Ctrl +).

## 3. Demo flow (about 10 minutes)

| Time | Show | Say |
|---|---|---|
| 0:00 | Title / problem | "Paste one file into ChatGPT and it can't see who calls the function, whether user input reaches it, or what breaks if it changes. We give the AI exactly that context, and nothing more." |
| 1:00 | Pipeline (README table) | "Deterministic before probabilistic: cheap static analysis finds candidates, the graph supplies context, only the top findings go to the AI agents, and a deterministic validator checks every fix." |
| 2:00 | `python -m codeaudit audit examples/shopkart --run-tests --refactor-k 12 --labels examples/shopkart_labels.csv --open` | Read the 7 stage lines as they print. "23 candidates, triage dismissed 6." |
| 3:30 | Report → dependency graph | "Red arrows: orders ⇄ inventory import each other. The tool found that inventory → orders is used **only by dead code**, so deleting `restock_value` breaks the cycle. A single-file tool can't see this." |
| 4:30 | Click F002 (SQL injection) | "Taint path from `input()` in main → handle → get_user. Then compare `count_rows`: same f-string pattern, but every caller passes a constant, so triage dismisses it. Same pattern, different verdict, because of context." |
| 5:30 | Same finding → diff + checks | "The fix is a parameterised query. Six checks: syntax, same signature, compiles, the whole repo re-scanned (finding gone, nothing new), and the project's tests pass. We never trust a fix blindly." |
| 6:30 | `python -m codeaudit context examples/shopkart F002` | "This is exactly what the LLM receives: about 360 tokens instead of the whole repository." |
| 7:00 | `python -m codeaudit serve --open` → run **`demo_copy`** → Accept / Create PR branch | "Local web app: live progress, review each fix, accept it into the files or turn it into a pull-request branch." |
| 8:30 | Evaluation table in the report + your benchmark numbers | "Precision 0.78 → 1.00, false alarms 5 → 0. We're honest about the misses: one issue the rules can't find, and one the offline heuristic gets wrong but the LLM catches." |
| 9:15 | (if Wi-Fi is good) `audit https://github.com/we45/Vulnerable-Flask-App --provider offline --open` | "A real, deliberately vulnerable app we didn't write: SQL injection, two template injections, unsafe YAML, MD5 passwords, in about 1.5 seconds, plus a validated SQLi fix." |
| 9:30 | (if Wi-Fi is good) `audit https://github.com/pallets/itsdangerous --provider offline` | "Works on real repositories in about 2 seconds. Here it correctly refuses to 'fix' SHA-1 inside HMAC signing, because that would break every existing signature." |

## 4. Likely questions

| Question | Answer |
|---|---|
| Why not give the whole repo to the LLM? | Context limits and cost, and more text makes models less accurate. The graph picks the ~300–3,000 tokens that matter for each finding. |
| Where exactly is the LLM used? | Triage (real or false alarm), Analyst (impact + plan), Refactorer (code). Parsing, graph, rules, ranking and validation are deterministic: reproducible and free. |
| What makes it "multi-agent"? | Four roles with separate inputs and outputs. The Refactorer calls tools (`get_callers`, `search` …) in a loop, and the Validator's rejection is fed back to it until it passes or gives up. |
| What if the AI is wrong? | A wrong fix is rejected by the Validator (it re-runs the whole analysis and the tests). A wrong verdict shows up in the precision/recall evaluation. If the AI is unreachable, that finding falls back to the heuristic agent. |
| How is dead code found? | Reachability over the call/reference graph from entry points (`__main__`, tests, framework decorators, exports). `_to_xml` is caught because its only caller is itself dead. |
| How do you handle `getattr` / dynamic calls? | If a name matches a dynamic `getattr` prefix or appears as a string, it's marked *possibly dynamic*, its confidence drops, and triage dismisses it (`handle_refund`). |
| How does ranking work? | severity × confidence × category weight × (1 + module PageRank) × blast-radius factor. A bug in code many functions depend on ranks higher. |
| Isn't 1.00 precision just because you built the test repo? | Partly, and we say so. The seeded repo proves the mechanism. The `labels_template.csv` the tool writes is how we label real repos next. We left in a known miss and a known heuristic mistake on purpose. |
| What's CWE? | MITRE's Common Weakness Enumeration, the standard catalogue of weakness types. Every security finding carries one (CWE-89 SQL injection, CWE-78 command injection …). |
| How is it different from SonarQube / Bandit? | They stop at pattern matching. We add repository context (taint path, reachability, cycle edges), AI triage that measurably removes false alarms, and validated automatic fixes as PRs. |
| Can the tool break my code? | It never edits the original during analysis: everything runs on a copy. Files change only when you press Accept (or `git apply` a patch), and PRs need review before merging. |
| Did you test it on real code? | Yes: Flask, Requests, itsdangerous, two deliberately vulnerable apps (we45 Vulnerable-Flask-App, dvpwa) and our own app Alai. README → "Tested on real repositories". |
| Why Python only? | Scope discipline. Python's `ast` gives exact trees; the graph, rules engine and agents are language-agnostic, so another language only needs a parser. |

## 5. If something breaks live

| Problem | Do this |
|---|---|
| Wi-Fi fails | Run the **exact same command** as tonight (same provider, key still set): the AI answers come from `.codeaudit_cache/`, no network needed. |
| API key / credit fails | Add `--provider offline`. The whole pipeline still runs with the heuristic agents. |
| Terminal error | Switch to the `report.html` tab you opened tonight. |
| Wi-Fi fails during a GitHub audit | Repos audited once are kept in `.codeaudit_repos/` and reused ("using existing clone"), so the same URL still works offline on this laptop. |
| Web UI port busy | `python -m codeaudit serve --port 8800` |
| Asked for a feature we don't have | "That's in Future work" (below). |

## 6. Future work (say it confidently)

1. Inter-procedural taint through return values (would catch `search_products`).
2. Type inference for `obj.method()` calls (better call resolution).
3. Labelled evaluation on 2–3 open-source repositories.
4. More languages (JavaScript / Java parsers feeding the same graph).
5. CI mode: run on every pull request and comment the findings.
