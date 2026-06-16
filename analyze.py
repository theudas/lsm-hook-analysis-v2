#!/usr/bin/env python3
"""
LSM Hook 参数与返回值分析（be5c6a84 输入格式）

目标：找出"用户态白名单(ir_json)不允许，但内核态实际监测到放行(LSM result=allow)"的文件操作。

数据约定（依据 be5c6a84 目录实测）：
  - 一个 round 由 round_id 目录唯一确定。round_end.json 的 time_start/time_end 是墙钟时间，
    而内核日志用 timestamp_mono_ns（单调时钟纳秒），两者基准不同、不可直接比较，
    因此 round 归属不依赖时间戳，而由目录 + 每条记录的 tool_call_id 保证。
    timestamp_mono_ns 仅用于 round 内排序。
  - kernel_lsm_hook_result.jsonl / kernel_syscall_seq.jsonl 已按目标进程切好，
    无需再做进程过滤。
  - 每条内核记录都自带 path，无需用 fd 回溯补全。
  - 内核已对每条记录打标 resource_role：
      declared_resource —— 用户态声明/授权的资源
      privacy_resource  —— 越权触达的隐私/系统资源
    本脚本同时用 ir_json 白名单独立判定，并交叉校验两者是否一致。
  - "实际执行了的操作"以 LSM file_open(result=allow) 为准：openat 返回 ENOENT(-2) 等
    失败的尝试不会产生 LSM 放行记录，不计为已执行。

每个 round 输出：
  - <round>/analysis_violations.jsonl  机器可读越权清单（每行一个 LSM 放行事件）
  - <round>/analysis_report.md         人类可读报告

服务器每天凌晨两点自动分析（cron）：

1. 编辑当前用户的 crontab：

crontab -e

2. 加入定时任务：

0 2 * * * cd /home/hx/try/lsm-hook-analysis-v2 && /usr/bin/python3 analyze.py >> analyze_cron.log 2>&1

3. 查看定时任务是否生效：

crontab -l

4. 查看自动分析日志：

tail -f /home/hx/try/lsm-hook-analysis-v2/analyze_cron.log

5. 停止自动分析：

crontab -e

删除或注释掉上面的 `0 2 * * * ... analyze.py ...` 这一行即可停止后续定时执行。
保存后用 `crontab -l` 确认该任务已不存在；如果脚本正好正在运行，可先用：

pgrep -af "python3 .*analyze.py"
kill <pid>

脚本会自动跳过已经生成 analysis_violations.jsonl 和 analysis_report.md 的 round，
因此每天运行不会重复覆盖已分析结果。新报告生成后会顺序上报到：

POST http://8.152.192.7:15100/api/rounds/detection/kernel

请求体：

{
"round_id": "<round_id>",
"judge_result_kernel_md_path": "<analysis_report.md 的绝对路径>"
}

只有收到 {"ok": true} 后才会写入 analysis_kernel_report_push.json；如果报告已存在
但该标记不存在，下次运行会跳过重新分析并补推该报告。单个 round 上报失败
会记录错误并继续处理后续 round。

可通过环境变量覆盖接口地址：

LHA_API_BASE_URL=http://host:port
LHA_KERNEL_REPORT_URL=http://host:port/api/rounds/detection/kernel
LHA_KERNEL_REPORT_PUSH_TIMEOUT=900
"""

import json
import logging
import os
import sys
import time
from pathlib import Path
from fnmatch import fnmatch
from urllib import error, request


SCRIPT_DIR = Path(__file__).parent
LOG_DIR = SCRIPT_DIR / "logs"
API_BASE_URL = os.environ.get("LHA_API_BASE_URL", "http://8.152.192.7:15100")
KERNEL_REPORT_URL = os.environ.get(
    "LHA_KERNEL_REPORT_URL",
    f"{API_BASE_URL.rstrip('/')}/api/rounds/detection/kernel",
)
KERNEL_REPORT_PUSH_TIMEOUT = int(os.environ.get("LHA_KERNEL_REPORT_PUSH_TIMEOUT", "900"))
PUSH_MARKER_NAME = "analysis_kernel_report_push.json"
ANALYZER_NAME = "lha_analyzer"


def setup_logging() -> logging.Logger:
    """同时写 cron/控制台输出和独立日志文件。"""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(ANALYZER_NAME)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    for handler in (
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "analyze.log", encoding="utf-8"),
    ):
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


log = setup_logging()


# --------------------------------------------------------------------------- #
# 解析输入
# --------------------------------------------------------------------------- #
def file_size(path: Path) -> int:
    return path.stat().st_size if path.is_file() else 0


def load_json_file(path: Path) -> dict:
    if not path.is_file():
        log.warning("输入 JSON 文件不存在 path=%s", path)
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.exception("输入 JSON 解析失败 path=%s size=%d bytes", path, file_size(path))
        raise
    log.info("已加载 JSON path=%s size=%d bytes keys=%s", path, file_size(path), sorted(data.keys()))
    return data


def load_jsonl(path: Path) -> list:
    if not path.is_file():
        log.warning("输入 JSONL 文件不存在 path=%s", path)
        return []
    rows = []
    try:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.strip():
                rows.append(json.loads(line))
    except json.JSONDecodeError:
        log.exception("输入 JSONL 解析失败 path=%s line=%d size=%d bytes", path, line_no, file_size(path))
        raise
    log.info("已加载 JSONL path=%s rows=%d size=%d bytes", path, len(rows), file_size(path))
    return rows


def parse_allowlist(round_end: dict) -> dict:
    """从 ir_json 展开用户态允许集合：文件路径 / 工具。"""
    allowed = {"files": set(), "tools": set(), "file_actions": {}}
    ir = json.loads(round_end.get("ir_json") or "{}")
    for pol in ir.get("level2", {}).get("policies", []):
        if pol.get("effect") != "allow":
            continue
        for obj in pol.get("objects", []):
            if obj.get("type") == "file":
                allowed["files"].add(obj["identifier"])
                allowed["file_actions"][obj["identifier"]] = obj.get("actions", [])
            elif obj.get("type") == "tool":
                allowed["tools"].add(obj["identifier"])
    return allowed


def parse_user_actions(round_end: dict) -> list:
    """从 action_json 取用户态实际记录的工具调用。"""
    actions = json.loads(round_end.get("action_json") or "[]")
    return [{"tool": a.get("tool"),
             "arguments": a.get("arguments", {}),
             "resources": a.get("resources", [])} for a in actions]


def parse_resource_facts(round_kernel: dict) -> list:
    """round_kernel.json 里 kernel_resource_facts 是字符串化的 JSON，含每路径汇总。"""
    raw = round_kernel.get("kernel_resource_facts")
    if not raw:
        log.info("round_kernel.kernel_resource_facts 为空")
        return []
    try:
        facts = json.loads(raw).get("resource_facts", [])
        log.info("已解析 kernel_resource_facts count=%d raw_len=%d", len(facts), len(raw))
        return facts
    except (json.JSONDecodeError, AttributeError):
        log.exception("kernel_resource_facts 解析失败 raw_len=%d", len(raw))
        return []


# --------------------------------------------------------------------------- #
# 内核事件关联
# --------------------------------------------------------------------------- #
def extract_kernel_file_ops(lsm: list, syscalls: list) -> list:
    """以 LSM file_open 事件为主线，经 related_event_id 关联其 syscall，附带读写字节。
       同一 open 对应的 read = 同 pid+fd、时间在本次 open 之后、且在该 fd 下一次 open 之前。"""
    sys_by_id = {s["event_id"]: s for s in syscalls}

    # 按 (pid, fd) 收集 open 时间点，用于界定每个 open 的有效区间（fd 会被复用）
    opens = {}
    reads = {}
    for s in syscalls:
        if s.get("action") == "open":
            ret = s.get("return_value")
            if isinstance(ret, int) and ret >= 0:
                opens.setdefault((s["pid"], ret), []).append(s["timestamp_mono_ns"])
        elif s.get("action") == "read":
            reads.setdefault((s["pid"], s["fd"]), []).append(
                (s["timestamp_mono_ns"], s.get("returned_bytes") or 0))
    for v in opens.values():
        v.sort()
    for v in reads.values():
        v.sort()

    ops = []
    for h in lsm:
        rs = sys_by_id.get(h.get("related_event_id"))
        open_fd = rs.get("return_value") if rs and rs.get("action") == "open" else None
        open_ts = h["timestamp_mono_ns"]

        # 本次 open 的有效区间 [open_ts, next_open_ts)，避免 fd 复用导致重复计入
        read_bytes = read_count = 0
        if isinstance(open_fd, int) and open_fd >= 0:
            later = [t for t in opens.get((h["pid"], open_fd), []) if t > open_ts]
            next_open_ts = min(later) if later else float("inf")
            for ts, nb in reads.get((h["pid"], open_fd), []):
                if open_ts <= ts < next_open_ts:
                    read_bytes += nb
                    read_count += 1

        ops.append({
            "event_id": h["event_id"],
            "hook_name": h["hook_name"],
            "result": h["result"],
            "return_value": h.get("return_value"),
            "pid": h["pid"],
            "tid": h.get("tid"),
            "timestamp_mono_ns": open_ts,
            "path": h.get("path"),
            "fd": h.get("fd"),
            "category": h.get("category"),
            "resource_role": h.get("resource_role"),
            "tool_call_id": h.get("tool_call_id"),
            "tool_name": h.get("tool_name"),
            "related_event_id": h.get("related_event_id"),
            "syscall": rs.get("syscall") if rs else None,
            "syscall_result": rs.get("result") if rs else None,
            "syscall_return_value": rs.get("return_value") if rs else None,
            "requested_bytes": rs.get("requested_bytes") if rs else None,
            "read_bytes": read_bytes,
            "read_count": read_count,
        })
    ops.sort(key=lambda r: r["timestamp_mono_ns"])
    return ops


# --------------------------------------------------------------------------- #
# 白名单比对
# --------------------------------------------------------------------------- #
def is_allowed(path: str, allowed_files: set) -> bool:
    if path is None:
        return False
    if path in allowed_files:
        return True
    for pat in allowed_files:  # 支持目录前缀 / glob
        if pat.endswith("/") and path.startswith(pat):
            return True
        if any(ch in pat for ch in "*?[") and fnmatch(path, pat):
            return True
    return False


# 越权分级：仅用于报告分类，不改变"是否越权"的判定
SENSITIVE_PREFIXES = (
    "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
    "/var/log/secure", "/var/log/", "/root/.ssh", "/root/.openclaw",
    "/proc/", "/run/secrets",
)
RUNTIME_PREFIXES = (
    "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/etc/ld.so.cache",
    "/usr/share/locale", "/usr/lib/locale", "/usr/bin", "/bin",
    "/etc/nsswitch.conf", "/run/systemd/userdb",
)


def classify(path: str) -> str:
    if path is None:
        return "unknown"
    if path.startswith(SENSITIVE_PREFIXES):
        return "sensitive"
    if path.startswith(RUNTIME_PREFIXES):
        return "runtime"
    return "other"


# --------------------------------------------------------------------------- #
# 单 round 分析
# --------------------------------------------------------------------------- #
def analyze_round(round_dir: Path) -> dict:
    started = time.monotonic()
    input_files = {
        "round_end": round_dir / "round_end.json",
        "round_kernel": round_dir / "round_kernel.json",
        "lsm": round_dir / "kernel_lsm_hook_result.jsonl",
        "syscalls": round_dir / "kernel_syscall_seq.jsonl",
    }
    log.info(
        "[%s] 开始分析 round_dir=%s files=%s",
        round_dir.name,
        round_dir,
        {name: {"exists": path.is_file(), "size": file_size(path)} for name, path in input_files.items()},
    )

    round_end = load_json_file(input_files["round_end"])
    round_kernel = load_json_file(input_files["round_kernel"])
    lsm = load_jsonl(round_dir / "kernel_lsm_hook_result.jsonl")
    syscalls = load_jsonl(round_dir / "kernel_syscall_seq.jsonl")

    allowed = parse_allowlist(round_end)
    user_actions = parse_user_actions(round_end)
    resource_facts = parse_resource_facts(round_kernel)
    kernel_ops = extract_kernel_file_ops(lsm, syscalls)
    log.info(
        "[%s] 输入解析完成 allowed_files=%d allowed_tools=%d user_actions=%d "
        "resource_facts=%d kernel_ops=%d",
        round_end.get("round_id", round_dir.name),
        len(allowed["files"]),
        len(allowed["tools"]),
        len(user_actions),
        len(resource_facts),
        len(kernel_ops),
    )

    violations = []
    role_ir_mismatch = 0
    for op in kernel_ops:
        ir_violation = not is_allowed(op["path"], allowed["files"])         # 判据①：ir_json 白名单
        role_violation = (op["resource_role"] == "privacy_resource")        # 判据②：内核打标
        if ir_violation != role_violation:
            role_ir_mismatch += 1
        if ir_violation or role_violation:
            v = dict(op)
            v["kernel_category"] = v.pop("category", None)  # 内核原始 category 字段
            v["category"] = classify(op["path"])            # 越权分级（敏感/运行时/其他）
            v["by_ir_json"] = ir_violation
            v["by_resource_role"] = role_violation
            v["judges_agree"] = (ir_violation == role_violation)
            violations.append(v)

    result = {
        "round_id": round_end.get("round_id", round_dir.name),
        "time_start": round_end.get("time_start"),
        "time_end": round_end.get("time_end"),
        "overall_score": round_end.get("overall_score"),
        "tool_name": round_kernel.get("round_id") and next(
            (o["tool_name"] for o in kernel_ops if o.get("tool_name")), None),
        "allowed_files": sorted(allowed["files"]),
        "allowed_tools": sorted(allowed["tools"]),
        "file_actions": allowed["file_actions"],
        "user_actions": user_actions,
        "resource_facts": resource_facts,
        "counts": {
            "lsm_total": len(lsm),
            "syscall_total": len(syscalls),
            "kernel_file_ops": len(kernel_ops),
            "violations": len(violations),
            "judge_mismatch": role_ir_mismatch,
        },
        "violations": violations,
    }
    counts = result["counts"]
    sensitive = sum(1 for v in violations if v["category"] == "sensitive")
    log.info(
        "[%s] 分析完成 elapsed=%.3fs lsm_total=%d syscall_total=%d kernel_file_ops=%d "
        "violations=%d sensitive=%d judge_mismatch=%d",
        result["round_id"],
        time.monotonic() - started,
        counts["lsm_total"],
        counts["syscall_total"],
        counts["kernel_file_ops"],
        counts["violations"],
        sensitive,
        counts["judge_mismatch"],
    )
    return result


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
def write_outputs(round_dir: Path, result: dict):
    started = time.monotonic()
    # JSONL：每行一个越权事件
    jl = round_dir / "analysis_violations.jsonl"
    with jl.open("w", encoding="utf-8") as f:
        for v in result["violations"]:
            f.write(json.dumps({"round_id": result["round_id"], **v}, ensure_ascii=False) + "\n")

    # Markdown 报告
    lines = []
    a = lines.append
    c = result["counts"]
    a(f"# 越权分析报告 — round `{result['round_id']}`\n")
    a(f"- 时间窗: {result['time_start']} → {result['time_end']}")
    a(f"- 工具: `{result['tool_name']}`")
    a(f"- 用户态判定得分: {result['overall_score']}")
    a(f"- 内核事件: LSM {c['lsm_total']} 条 / syscall {c['syscall_total']} 条 / "
      f"放行文件操作 {c['kernel_file_ops']} 个")
    a(f"- **越权操作: {c['violations']} 个**（ir_json 与内核 resource_role 判据分歧: "
      f"{c['judge_mismatch']} 处）\n")

    a("## 用户态允许集 (ir_json)\n")
    a("允许文件:")
    for p in result["allowed_files"]:
        acts = ", ".join(result["file_actions"].get(p, []))
        a(f"  - `{p}` （动作: {acts}）")
    a("允许工具: " + ", ".join(f"`{t}`" for t in result["allowed_tools"]) + "\n")

    a("## 用户态实际记录行为 (action_json)\n")
    for ua in result["user_actions"]:
        a(f"  - `{ua['tool']}` {json.dumps(ua['arguments'], ensure_ascii=False)}")
    a("")

    # 越权清单：按越权分级（敏感 / 其他 / 运行时 / 未知）分组
    by_cat = {}
    for v in result["violations"]:
        by_cat.setdefault(v["category"], []).append(v)
    cat_title = {"sensitive": "🔴 敏感越权", "runtime": "🟡 运行时加载",
                 "other": "⚪ 其他", "unknown": "❔ 未知路径"}
    a("## 越权清单（内核 LSM 放行，但用户态不允许）\n")
    for cat in ("sensitive", "other", "runtime", "unknown"):
        items = by_cat.get(cat)
        if not items:
            continue
        a(f"### {cat_title[cat]} ({len(items)})\n")
        a("| path | hook | result | pid | event_id | rel_syscall | 读取字节 | 判据一致 |")
        a("|---|---|---|---|---|---|---|---|")
        for v in items:
            agree = "✓" if v["judges_agree"] else "⚠ 分歧"
            a(f"| `{v['path']}` | {v['hook_name']} | {v['result']} | {v['pid']} | "
              f"{v['event_id']} | {v['related_event_id']} | {v['read_bytes']} | {agree} |")
        a("")

    # round_kernel.json 资源事实佐证
    if result["resource_facts"]:
        a("## 内核资源事实佐证 (round_kernel.kernel_resource_facts)\n")
        a("| path | actions | open_count | read_count | read_bytes | lsm_allow_count |")
        a("|---|---|---|---|---|---|")
        for rf in result["resource_facts"]:
            a(f"| `{rf.get('path')}` | {', '.join(rf.get('actions', []))} | "
              f"{rf.get('open_count', '')} | {rf.get('read_count', '')} | "
              f"{rf.get('read_returned_bytes', '')} | {rf.get('lsm_allow_count', '')} |")
        a("")

    md = round_dir / "analysis_report.md"
    md.write_text("\n".join(lines), encoding="utf-8")
    log.info(
        "[%s] 分析产物写入完成 elapsed=%.3fs violations_path=%s violations_size=%d bytes "
        "report_path=%s report_size=%d bytes",
        result["round_id"],
        time.monotonic() - started,
        jl,
        file_size(jl),
        md,
        file_size(md),
    )
    return jl, md


def already_analyzed(round_dir: Path) -> bool:
    """分析产物都存在时，认为该 round 已经分析过。"""
    return (
        (round_dir / "analysis_violations.jsonl").is_file()
        and (round_dir / "analysis_report.md").is_file()
    )


def already_pushed(round_dir: Path) -> bool:
    """接口确认 ok 后才写入该标记；存在即认为前端展示上报已完成。"""
    return (round_dir / PUSH_MARKER_NAME).is_file()


def is_mock_round(round_dir: Path) -> bool:
    """mock round 只用于本地测试，不应推送到正式展示接口。"""
    for name in ("round_end.json", "round_kernel.json"):
        path = round_dir / name
        if not path.is_file():
            continue
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if metadata.get("is_mock") is True:
            return True
    return False


def load_round_id(round_dir: Path) -> str:
    round_end_path = round_dir / "round_end.json"
    if not round_end_path.is_file():
        log.warning("[%s] 缺少 round_end.json，使用目录名作为 round_id", round_dir.name)
        return round_dir.name
    try:
        round_end = json.loads(round_end_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.exception("[%s] round_end.json 解析失败，使用目录名作为 round_id path=%s", round_dir.name, round_end_path)
        return round_dir.name
    return round_end.get("round_id") or round_dir.name


def push_kernel_report(round_id: str, report_path: Path) -> dict:
    """把内核态判断结果 Markdown 路径上报给前端展示接口。"""
    started = time.monotonic()
    payload = {
        "round_id": round_id,
        "judge_result_kernel_md_path": str(report_path.resolve()),
    }
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    log.info(
        "[%s] 开始上报内核分析报告 url=%s timeout=%ss payload=%s payload_size=%d bytes "
        "report_exists=%s report_size=%d bytes",
        round_id,
        KERNEL_REPORT_URL,
        KERNEL_REPORT_PUSH_TIMEOUT,
        payload,
        len(data),
        report_path.is_file(),
        file_size(report_path),
    )
    req = request.Request(
        KERNEL_REPORT_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=KERNEL_REPORT_PUSH_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        log.exception(
            "[%s] 上报失败 HTTPError status=%s elapsed=%.3fs body=%s",
            round_id,
            exc.code,
            time.monotonic() - started,
            body,
        )
        raise RuntimeError(f"上报失败: HTTP {exc.code} {body}") from exc
    except error.URLError as exc:
        log.exception("[%s] 上报失败 URLError elapsed=%.3fs error=%s", round_id, time.monotonic() - started, exc)
        raise RuntimeError(f"上报失败: {exc}") from exc

    try:
        result = json.loads(body)
    except json.JSONDecodeError as exc:
        log.exception("[%s] 上报失败，响应不是 JSON elapsed=%.3fs body=%s", round_id, time.monotonic() - started, body)
        raise RuntimeError(f"上报失败: 响应不是 JSON: {body}") from exc
    if result.get("ok") is not True:
        log.error("[%s] 上报失败，响应未返回 ok=true elapsed=%.3fs response=%s", round_id, time.monotonic() - started, result)
        raise RuntimeError(f"上报失败: 响应未返回 ok=true: {result}")
    log.info(
        "[%s] 上报成功 elapsed=%.3fs response=%s",
        round_id,
        time.monotonic() - started,
        result,
    )
    return result


def mark_report_pushed(round_dir: Path, round_id: str, report_path: Path, response: dict) -> None:
    marker = {
        "round_id": round_id,
        "judge_result_kernel_md_path": str(report_path.resolve()),
        "endpoint": KERNEL_REPORT_URL,
        "response": response,
    }
    marker_path = round_dir / PUSH_MARKER_NAME
    marker_path.write_text(
        json.dumps(marker, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log.info(
        "[%s] 已写入上报标记 marker_path=%s marker_size=%d bytes endpoint=%s",
        round_id,
        marker_path,
        file_size(marker_path),
        KERNEL_REPORT_URL,
    )


def push_and_mark_report(round_dir: Path, round_id: str, report_path: Path) -> bool:
    try:
        response = push_kernel_report(round_id, report_path)
    except RuntimeError as exc:
        log.error("[%s] 上报失败，继续处理后续 round error=%s report_path=%s", round_id, exc, report_path)
        return False

    mark_report_pushed(round_dir, round_id, report_path, response)
    log.info("[%s] 上报成功 -> %s", round_id, KERNEL_REPORT_URL)
    return True


# --------------------------------------------------------------------------- #
def main():
    started = time.monotonic()
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else SCRIPT_DIR / "input"
    log.info(
        "分析任务启动 base=%s api_url=%s push_timeout=%ss log_file=%s",
        base,
        KERNEL_REPORT_URL,
        KERNEL_REPORT_PUSH_TIMEOUT,
        (LOG_DIR / "analyze.log").resolve(),
    )
    round_dirs = [d for d in sorted(base.iterdir())
                  if d.is_dir() and (d / "round_end.json").is_file()] if base.is_dir() else []
    if not round_dirs and (base / "round_end.json").is_file():
        round_dirs = [base]
    if not round_dirs:
        log.warning("未找到任何 round 目录(需含 round_end.json): %s", base)
        return

    log.info("发现 round 目录 count=%d dirs=%s", len(round_dirs), [str(d) for d in round_dirs])
    analyzed_count = 0
    skipped_count = 0
    pushed_count = 0
    failed_push_count = 0
    for rd in round_dirs:
        round_id = load_round_id(rd)
        if is_mock_round(rd):
            skipped_count += 1
            log.info("[%s] mock round，跳过分析和正式上报 round_dir=%s", round_id, rd)
            continue

        if already_analyzed(rd):
            report_path = rd / "analysis_report.md"
            skipped_count += 1
            if already_pushed(rd):
                log.info(
                    "[%s] 已存在分析结果且已上报，跳过 round_dir=%s report_path=%s marker_path=%s",
                    round_id,
                    rd,
                    report_path,
                    rd / PUSH_MARKER_NAME,
                )
                continue

            log.info("[%s] 已存在分析结果但未上报，开始补推 report_path=%s", round_id, report_path)
            if push_and_mark_report(rd, round_id, report_path):
                pushed_count += 1
            else:
                failed_push_count += 1
            continue

        res = analyze_round(rd)
        _, report_path = write_outputs(rd, res)
        analyzed_count += 1
        c = res["counts"]
        sensitive = sum(1 for v in res["violations"] if v["category"] == "sensitive")
        log.info(
            "[%s] 分析结果摘要 LSM放行=%d 越权=%d 敏感=%d 判据分歧=%d round_dir=%s",
            res["round_id"],
            c["kernel_file_ops"],
            c["violations"],
            sensitive,
            c["judge_mismatch"],
            rd,
        )

        if push_and_mark_report(rd, res["round_id"], report_path):
            pushed_count += 1
        else:
            failed_push_count += 1

    log.info(
        "分析任务完成 elapsed=%.3fs total=%d new_analyzed=%d skipped=%d pushed=%d failed_push=%d "
        "outputs=analysis_violations.jsonl,analysis_report.md",
        time.monotonic() - started,
        len(round_dirs),
        analyzed_count,
        skipped_count,
        pushed_count,
        failed_push_count,
    )


if __name__ == "__main__":
    main()
