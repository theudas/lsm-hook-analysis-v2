"""
Socket.IO 接收端：监听监控服务的 push 事件，落盘 round_end / round_kernel 数据。

只处理 round_end 和 round_kernel 两种消息，按 round_id 分目录存到 input/ 下。
round_kernel 中的 syscall_seq / lsm_hook_result 是服务端文件路径，本脚本假定
本地可访问（同机或共享盘），会把文件内容拷贝进对应 round 目录。
"""

import json
import logging
import shutil
from pathlib import Path

import socketio

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
SERVER_URL = "ws://8.152.192.7:15100"
SOCKETIO_PATH = "/wss"
NAMESPACE = "/wss/monitor"
INPUT_DIR = Path(__file__).parent / "input"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("receiver")


# ---------------------------------------------------------------------------
# Socket.IO 客户端（开启断线自动重连）
# ---------------------------------------------------------------------------
sio = socketio.Client(
    reconnection=True,
    reconnection_attempts=0,      # 0 = 无限次重试
    reconnection_delay=1,         # 首次重连间隔（秒）
    reconnection_delay_max=30,    # 重连间隔上限（秒）
    logger=False,
    engineio_logger=False,
)


# ---------------------------------------------------------------------------
# 落盘辅助
# ---------------------------------------------------------------------------
def round_dir(round_id: str) -> Path:
    """返回（并创建）某个 round 的输出目录。"""
    d = INPUT_DIR / round_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_message(round_id: str, name: str, data: dict) -> None:
    """把整条消息以格式化 JSON 存盘。"""
    path = round_dir(round_id) / f"{name}.json"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("已保存 %s -> %s", name, path)


def copy_kernel_file(round_id: str, src_path: str, dst_name: str) -> None:
    """把服务端给出的文件路径拷贝进 round 目录；路径无效则告警跳过。"""
    if not src_path:
        log.warning("[%s] %s 路径为空，跳过", round_id, dst_name)
        return
    src = Path(src_path)
    if not src.is_file():
        log.warning("[%s] 文件不存在或不可访问，跳过拷贝: %s", round_id, src_path)
        return
    dst = round_dir(round_id) / dst_name
    shutil.copy2(src, dst)
    log.info("[%s] 已拷贝 %s -> %s", round_id, src_path, dst)


# ---------------------------------------------------------------------------
# 事件处理
# ---------------------------------------------------------------------------
@sio.on("push", namespace=NAMESPACE)
def on_push(data):
    if not isinstance(data, dict):
        log.warning("收到非字典消息，忽略: %r", data)
        return

    push_type = data.get("push_type")
    round_id = data.get("round_id")

    if not round_id:
        log.warning("消息缺少 round_id，忽略: push_type=%s", push_type)
        return

    if push_type == "round_end":
        log.info("[%s] round_end  score=%s", round_id, data.get("overall_score"))
        save_message(round_id, "round_end", data)

    elif push_type == "round_kernel":
        log.info("[%s] round_kernel", round_id)
        save_message(round_id, "round_kernel", data)
        copy_kernel_file(
            round_id, data.get("kernel_syscall_seq"), "kernel_syscall_seq.jsonl"
        )
        copy_kernel_file(
            round_id, data.get("kernel_lsm_hook_result"), "kernel_lsm_hook_result.jsonl"
        )

    else:
        # round_start / round_ir_ready 等其余类型按需求忽略
        log.debug("[%s] 忽略 push_type=%s", round_id, push_type)


@sio.event(namespace=NAMESPACE)
def connect():
    log.info("已连接到 %s%s", SERVER_URL, NAMESPACE)


@sio.event(namespace=NAMESPACE)
def disconnect():
    log.warning("连接断开，等待自动重连...")


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def main():
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    log.info("数据将保存到: %s", INPUT_DIR.resolve())
    sio.connect(
        SERVER_URL,
        socketio_path=SOCKETIO_PATH,
        namespaces=[NAMESPACE],
        transports=["websocket"],
    )
    sio.wait()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("收到中断，退出。")
    finally:
        if sio.connected:
            sio.disconnect()
