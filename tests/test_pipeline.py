import json

from codeaudit.agents.llm import LLM
from codeaudit.cli import main as cli
from codeaudit.evaluate import compare_triage
from codeaudit.pipeline import AuditOptions, run
from codeaudit.pr import export_prs, git

from conftest import LABELS


def test_offline_pipeline_end_to_end(shopkart, tmp_path):
    out = tmp_path / "out"
    data = run(AuditOptions(repo=str(shopkart), out_dir=str(out), provider="offline", run_tests=True,
                            refactor_k=20, labels=str(LABELS)), progress=lambda m: None)
    s = data["summary"]
    assert s["tests"] == "baseline tests pass" and s["patches"] >= 10
    ev = data["evaluation"]
    assert ev["before_triage"]["fp"] == 5 and ev["after_triage"]["fp"] == 0
    assert ev["missed"] == ["SQL_INJECTION:shopkart.db:search_products"]
    for f in ("report.html", "results.json", "graph.json", "labels_template.csv"):
        assert (out / f).exists()
    assert len(list((out / "patches").glob("*.diff"))) == s["patches"]
    html = (out / "report.html").read_text()
    assert "Module dependency graph" in html and "<svg" in html and "Evaluation against ground truth" in html


def test_llm_pipeline_with_agent_loop_and_feedback(shopkart, tmp_path, fake_llm_server):
    llm = LLM("anthropic", base_url=fake_llm_server.url, api_key="k", cache_dir=str(tmp_path / "c"), retry_wait=0)
    data = run(AuditOptions(repo=str(shopkart), out_dir=str(tmp_path / "out"), refactor_k=20, run_tests=True,
                            labels=str(LABELS)), progress=lambda m: None, llm=llm)
    res = {r["finding"]["key"]: r for r in data["results"]}
    # LLM triage catches the password hash the heuristic misses
    pw = res["WEAK_HASH:shopkart.auth:password_key:hashlib.sha1"]["triage"]
    assert pw["mode"] == "llm" and pw["verdict"] == "TRUE_POSITIVE" and pw["heuristic_verdict"] == "FALSE_POSITIVE"
    assert data["evaluation"]["after_triage"]["recall"] > 0.9 and data["evaluation"]["after_triage"]["fp"] == 0
    # agent loop: tool call, rejected first submission, accepted second
    rf = res["SQL_INJECTION:shopkart.db:get_user:cur.execute"]["refactor"]
    assert rf["ok"] and rf["by"] == "llm-agent" and rf["attempts"] == 2
    actions = [t["action"] for t in rf["transcript"]]
    assert actions[0].startswith("get_callers") and "REJECTED" in rf["transcript"][1]["result"]
    # dead code deleted by the agent
    assert res["DEAD_CODE:shopkart.inventory:export_xml"]["refactor"]["by"] == "llm-agent"
    # broken LLM code -> deterministic fallback still produces a validated patch
    fo = res["SQL_INJECTION:shopkart.db:find_orders:conn.execute"]["refactor"]
    assert fo["ok"] and fo["by"] == "deterministic" and fo["llm_attempt"]["attempts"] == 3
    # multi-turn Anthropic requests send the assistant's content blocks back unchanged
    multi = [r for r in fake_llm_server.requests if len(r["body"].get("messages", [])) > 1]
    assert multi and multi[0]["body"]["messages"][1]["content"][0]["type"] == "thinking"


def test_llm_failure_falls_back_to_heuristics(shopkart, tmp_path, fake_llm_server):
    fake_llm_server.fail_with = 500
    llm = LLM("openai", base_url=fake_llm_server.url, api_key="k", cache_dir=str(tmp_path / "c"), retry_wait=0)
    data = run(AuditOptions(repo=str(shopkart), out_dir=str(tmp_path / "out"), triage_k=3, top_k=2, refactor_k=1),
               progress=lambda m: None, llm=llm)
    t = data["results"][0]["triage"]
    assert t["mode"].startswith("heuristic (LLM failed")
    assert data["results"][0]["refactor"]["ok"]                               # deterministic fallback


def test_benchmark_compares_heuristic_and_llm(shopkart, tmp_path, fake_llm_server):
    llm = LLM("anthropic", base_url=fake_llm_server.url, api_key="k", cache_dir=str(tmp_path))
    table = compare_triage(str(shopkart), str(LABELS), [LLM("offline"), llm], log=lambda m: None)
    static, heur, ai = table
    assert static["fp"] == 5 and heur["fp"] == 0
    assert "WEAK_HASH:shopkart.auth:password_key:hashlib.sha1" in heur["mistakes"]
    assert ai["recall"] > heur["recall"]


def test_pr_branches_in_sandbox(shopkart, tmp_path):
    out = tmp_path / "out"
    run(AuditOptions(repo=str(shopkart), out_dir=str(out), provider="offline", refactor_k=3), progress=lambda m: None)
    rows = export_prs(str(out), sandbox=True, log=lambda m: None)
    assert len(rows) == 3 and all("commit" in r for r in rows)
    sb = str(out / "pr_sandbox")
    branches = git(sb, "branch", "--list", "codeaudit/*")
    assert branches.count("codeaudit/") == 3
    assert "?" in git(sb, "show", f"{rows[0]['branch']}:shopkart/db.py") or rows[0]["finding"] != "F001"
    assert json.loads((out / "prs.json").read_text())["prs"]


def test_cli_audit_and_context(shopkart, tmp_path, capsys):
    cli(["audit", str(shopkart), "--provider", "offline", "--out", str(tmp_path / "o"), "--labels", str(LABELS)])
    assert "after triage" in capsys.readouterr().out
    cli(["context", str(shopkart), "F002"])
    out = capsys.readouterr().out
    assert "Repository facts" in out and "tokens sent to the LLM" in out
