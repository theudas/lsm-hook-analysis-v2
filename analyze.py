#!/usr/bin/env python3
"""
LSM Hook 参数与返回值分析

目标：找出"用户态白名单(ir_json)不允许，但内核态实际监测到执行了"的文件操作。

约定（依据数据所有者确认）：
  - 一个 round 由 round_id 目录唯一确定，内核日志已由服务端按 round 切分，
    无需用时间戳判定归属。timestamp_mono_ns 仅用于 round 内排序与 syscall<->lsm 关联。
  - 内核日志中的所有记录都由 openclaw 产生，不做任何进程过滤，直接逐条对照白名单。

每个 round 输出：
  - <round>/analysis_violations.jsonl  机器可读的越权清单（每行一个内核文件操作）
  - <round>/analysis_report.md         人类可读报告
"""

import json
import sys
from pathlib import Path
from fnmatch import fnmatch


# --------------------------------------------------------------------------- #
# 解析输入
# --------------------------------------------------------------------------- #
def load_jsonl(path: Path) -> list:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def parse_allowlist(round_end: dict) -> dict:
    """从 ir_json 展开用户态允许集合：文件路径 / 工具 / 动作。"""
    allowed = {"files": set(), "tools": set(), "raw_objects": []}
    ir = json.loads(round_end.get("ir_json") or "{}")
    for pol in ir.get("level2", {}).get("policies", []):
        if pol.get("effect") != "allow":
            continue
        for obj in pol.get("objects", []):
            allowed["raw_objects"].append(obj)
            if obj.get("type") == "file":
                allowed["files"].add(obj["identifier"])
            elif obj.get("type") == "tool":
                allowed["tools"].add(obj["identifier"])
    return allowed


def parse_user_actions(round_end: dict) -> list:
    """从 action_json 取用户态实际记录的工具调用。"""
    actions = json.loads(round_end.get("action_json") or "[]")
    out = []
    for a in actions:
        out.append({"tool": a.get("tool"), "arguments": a.get("arguments", {}),
                    "resources": a.get("resources", [])})
    return out


# --------------------------------------------------------------------------- #
# 内核事件关联与补全
# --------------------------------------------------------------------------- #
def build_fd_table(syscalls: list) -> dict:
    """按时间顺序重建 (pid, fd) -> path，用于给只有 fd 的事件补 path。
       openat 的 return_value 即分配的 fd。"""
    fd_table = {}
    timeline = {}  # (pid, fd) -> list[(ts, path)]
    for s in sorted(syscalls, key=lambda r: r["timestamp_mono_ns"]):
        if s["syscall_name"] == "openat":
            fd = s.get("return_value")
            path = s.get("args", {}).get("path")
            if isinstance(fd, int) and fd >= 0 and path:
                timeline.setdefault((s["pid"], fd), []).append((s["timestamp_mono_ns"], path))
    return timeline


def resolve_fd_path(timeline: dict, pid: int, fd: int, ts: int):
    """找该 pid+fd 在 ts 之前最近一次 open 的 path。"""
    cands = [p for (t, p) in timeline.get((pid, fd), []) if t <= ts]
    return cands[-1] if cands else None


def extract_kernel_file_ops(lsm: list, syscalls: list) -> list:
    """把内核态所有文件操作规整成统一记录，并尽量补全 path。"""
    sys_by_id = {s["event_id"]: s for s in syscalls}
    fd_timeline = build_fd_table(syscalls)
    ops = []
    for h in lsm:
        target = h.get("target", {})
        path = target.get("path")
        fd = target.get("fd")
        # 无 path（如 file_permission）时，借关联 syscall 的 fd 回溯
        if not path:
            rs = sys_by_id.get(h.get("related_syscall_event_id"))
            if rs:
                use_fd = rs.get("args", {}).get("fd", fd)
                path = resolve_fd_path(fd_timeline, h["pid"], use_fd, h["timestamp_mono_ns"])
        ops.append({
            "event_id": h["event_id"],
            "hook_name": h["hook_name"],
            "hook_result": h["hook_result"],
            "return_value": h.get("return_value"),
            "pid": h["pid"],
            "tid": h.get("tid"),
            "timestamp_mono_ns": h["timestamp_mono_ns"],
            "path": path,
            "path_resolved_from_fd": (not target.get("path")) and bool(path),
            "fd": fd,
            "related_syscall_event_id": h.get("related_syscall_event_id"),
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
    # 支持白名单里写目录前缀或 glob
    for pat in allowed_files:
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
    round_end = json.loads((round_dir / "round_end.json").read_text(encoding="utf-8")) \
        if (round_dir / "round_end.json").is_file() else {}
    lsm = load_jsonl(round_dir / "kernel_lsm_hook_result.jsonl")
    syscalls = load_jsonl(round_dir / "kernel_syscall_seq.jsonl")

    allowed = parse_allowlist(round_end)
    user_actions = parse_user_actions(round_end)
    kernel_ops = extract_kernel_file_ops(lsm, syscalls)

    violations = []
    for op in kernel_ops:
        if not is_allowed(op["path"], allowed["files"]):
            op = dict(op)
            op["category"] = classify(op["path"])
            violations.append(op)

    return {
        "round_id": round_end.get("round_id", round_dir.name),
        "time_start": round_end.get("time_start"),
        "time_end": round_end.get("time_end"),
        "overall_score": round_end.get("overall_score"),
        "allowed_files": sorted(allowed["files"]),
        "allowed_tools": sorted(allowed["tools"]),
        "user_actions": user_actions,
        "counts": {
            "lsm_total": len(lsm),
            "syscall_total": len(syscalls),
            "kernel_file_ops": len(kernel_ops),
            "violations": len(violations),
        },
        "violations": violations,
    }


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
def write_outputs(round_dir: Path, result: dict) -> None:
    # JSONL：每行一个越权事件
    jl = round_dir / "analysis_violations.jsonl"
    with jl.open("w", encoding="utf-8") as f:
        for v in result["violations"]:
            f.write(json.dumps({"round_id": result["round_id"], **v}, ensure_ascii=False) + "\n")

    # Markdown 报告
    md = round_dir / "analysis_report.md"
    lines = []
    a = lines.append
    a(f"# 越权分析报告 — round `{result['round_id']}`\n")
    a(f"- 时间窗(墙钟): {result['time_start']} → {result['time_end']}")
    a(f"- 用户态判定得分: {result['overall_score']}")
    c = result["counts"]
    a(f"- 内核事件: LSM {c['lsm_total']} 条 / syscall {c['syscall_total']} 条 / 文件操作 {c['kernel_file_ops']} 个")
    a(f"- **越权操作: {c['violations']} 个**\n")

    a("## 用户态允许集 (ir_json)\n")
    a("允许文件:")
    for p in result["allowed_files"]:
        a(f"  - `{p}`")
    a("允许工具: " + ", ".join(f"`{t}`" for t in result["allowed_tools"]) + "\n")

    a("## 用户态实际记录行为 (action_json)\n")
    for ua in result["user_actions"]:
        a(f"  - `{ua['tool']}` {json.dumps(ua['arguments'], ensure_ascii=False)}")
    a("")

    # 按分级分组
    by_cat = {}
    for v in result["violations"]:
        by_cat.setdefault(v["category"], []).append(v)
    cat_title = {"sensitive": "🔴 敏感越权", "runtime": "🟡 运行时加载",
                 "other": "⚪ 其他", "unknown": "❔ 未知路径"}
    a("## 越权清单（内核执行但白名单不允许）\n")
    for cat in ("sensitive", "other", "runtime", "unknown"):
        items = by_cat.get(cat)
        if not items:
            continue
        a(f"### {cat_title[cat]} ({len(items)})\n")
        a("| path | hook | pid | event_id | rel_syscall |")
        a("|---|---|---|---|---|")
        for v in items:
            note = " *(fd回溯)*" if v["path_resolved_from_fd"] else ""
            a(f"| `{v['path']}`{note} | {v['hook_name']} | {v['pid']} | "
              f"{v['event_id']} | {v['related_syscall_event_id']} |")
        a("")

    md.write_text("\n".join(lines), encoding="utf-8")
    return jl, md


# --------------------------------------------------------------------------- #
def main():
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "input"
    round_dirs = [d for d in sorted(base.iterdir()) if d.is_dir() and (d / "round_end.json").is_file()] \
        if base.is_dir() else []
    if not round_dirs:
        # 也允许直接传单个 round 目录
        if (base / "round_end.json").is_file():
            round_dirs = [base]
        else:
            print(f"未找到任何 round 目录(需含 round_end.json): {base}")
            return

    summary = []
    for rd in round_dirs:
        res = analyze_round(rd)
        write_outputs(rd, res)
        summary.append(res)
        c = res["counts"]
        print(f"[{res['round_id']}] 文件操作 {c['kernel_file_ops']} → 越权 {c['violations']} "
              f"(敏感 {sum(1 for v in res['violations'] if v['category']=='sensitive')})  -> {rd}")

    print(f"\n完成 {len(summary)} 个 round。每个 round 目录下已生成 "
          f"analysis_violations.jsonl 和 analysis_report.md")


if __name__ == "__main__":
    main()
