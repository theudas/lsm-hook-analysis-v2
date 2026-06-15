"""
Socket.IO 接收端：监听监控服务的 push 事件，落盘 round_end / round_kernel 数据。

只处理 round_end 和 round_kernel 两种消息，按 round_id 分目录存到 input/ 下。
round_kernel 中的 syscall_seq / lsm_hook_result 是服务端文件路径，本脚本假定
本地可访问（同机或共享盘），会把文件内容拷贝进对应 round 目录。

服务器持久运行部署方式（systemd）：

1. 创建服务文件：

sudo tee /etc/systemd/system/lha_receiver.service >/dev/null <<'EOF'
[Unit]
Description=LHA Socket.IO Receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/hx/try/lsm-hook-analysis-v2
ExecStart=/usr/bin/python3 /home/hx/try/lsm-hook-analysis-v2/receiver.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF


2. 启动并设置开机自启：

sudo systemctl daemon-reload
sudo systemctl enable --now lha_receiver.service

3. 查看状态和实时日志：

systemctl status lha_receiver.service
journalctl -u lha_receiver.service -f

4. 重启或停止：

sudo systemctl restart lha_receiver.service
sudo systemctl stop lha_receiver.service
"""

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path

import socketio

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
SERVER_URL = "ws://8.152.192.7:15100"
SOCKETIO_PATH = "/wss"
NAMESPACE = "/wss/monitor"
INPUT_DIR = Path(__file__).parent / "input"
LOG_DIR = Path(__file__).parent / "logs"
RECEIVER_NAME = "lha_receiver"


def setup_logging() -> logging.Logger:
    """同时输出到 systemd/控制台和本地日志文件，便于实时看和事后追踪。"""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(RECEIVER_NAME)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    for handler in (
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "receiver.log", encoding="utf-8"),
    ):
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


log = setup_logging()


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
def json_size(data: dict) -> int:
    """返回消息序列化后的字节数，用于判断收到的信息规模。"""
    return len(json.dumps(data, ensure_ascii=False).encode("utf-8"))


def safe_len(value) -> int:
    if value is None:
        return 0
    return len(str(value))


def round_dir(round_id: str) -> Path:
    """返回（并创建）某个 round 的输出目录。"""
    d = INPUT_DIR / round_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_message(round_id: str, name: str, data: dict) -> None:
    """把整条消息以格式化 JSON 存盘。"""
    path = round_dir(round_id) / f"{name}.json"
    raw = json.dumps(data, ensure_ascii=False, indent=2)
    path.write_text(raw, encoding="utf-8")
    log.info(
        "[%s] 已保存消息 name=%s path=%s size=%d bytes",
        round_id,
        name,
        path,
        path.stat().st_size,
    )


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
    log.info(
        "[%s] 开始拷贝内核文件 src=%s dst=%s src_size=%d bytes",
        round_id,
        src,
        dst,
        src.stat().st_size,
    )
    shutil.copy2(src, dst)
    log.info(
        "[%s] 内核文件拷贝完成 src=%s dst=%s dst_size=%d bytes",
        round_id,
        src_path,
        dst,
        dst.stat().st_size,
    )


# ---------------------------------------------------------------------------
# 事件处理
# ---------------------------------------------------------------------------
@sio.on("push", namespace=NAMESPACE)
def on_push(data):
    if not isinstance(data, dict):
        log.warning(
            "收到非字典消息，忽略 received_at=%s data_type=%s data=%r",
            datetime.now().isoformat(timespec="seconds"),
            type(data).__name__,
            data,
        )
        return

    push_type = data.get("push_type")
    round_id = data.get("round_id")
    received_at = datetime.now().isoformat(timespec="seconds")
    log.info(
        "[%s] 收到 push 消息 received_at=%s push_type=%s push_time=%s keys=%s size=%d bytes",
        round_id or "-",
        received_at,
        push_type,
        data.get("push_time"),
        sorted(data.keys()),
        json_size(data),
    )

    if not round_id:
        log.warning(
            "消息缺少 round_id，忽略 push_type=%s push_time=%s keys=%s",
            push_type,
            data.get("push_time"),
            sorted(data.keys()),
        )
        return

    if push_type == "round_end":
        log.info(
            "[%s] round_end 摘要 overall_score=%s time_start=%s time_end=%s "
            "is_mock=%s action_json_len=%d ir_json_len=%d",
            round_id,
            data.get("overall_score"),
            data.get("time_start"),
            data.get("time_end"),
            data.get("is_mock"),
            safe_len(data.get("action_json")),
            safe_len(data.get("ir_json")),
        )
        save_message(round_id, "round_end", data)

    elif push_type == "round_kernel":
        syscall_path = data.get("kernel_syscall_seq")
        lsm_path = data.get("kernel_lsm_hook_result")
        log.info(
            "[%s] round_kernel 摘要 is_mock=%s syscall_path=%s syscall_exists=%s "
            "lsm_path=%s lsm_exists=%s resource_facts_len=%d",
            round_id,
            data.get("is_mock"),
            syscall_path,
            Path(syscall_path).is_file() if syscall_path else False,
            lsm_path,
            Path(lsm_path).is_file() if lsm_path else False,
            safe_len(data.get("kernel_resource_facts")),
        )
        save_message(round_id, "round_kernel", data)
        copy_kernel_file(
            round_id, data.get("kernel_syscall_seq"), "kernel_syscall_seq.jsonl"
        )
        copy_kernel_file(
            round_id, data.get("kernel_lsm_hook_result"), "kernel_lsm_hook_result.jsonl"
        )

    else:
        # round_start / round_ir_ready 等其余类型按需求忽略
        log.info(
            "[%s] 忽略未处理的 push_type=%s push_time=%s keys=%s",
            round_id,
            push_type,
            data.get("push_time"),
            sorted(data.keys()),
        )


@sio.event(namespace=NAMESPACE)
def connect():
    log.info("已连接到 server=%s namespace=%s socketio_path=%s", SERVER_URL, NAMESPACE, SOCKETIO_PATH)


@sio.event(namespace=NAMESPACE)
def disconnect():
    log.warning("连接断开，等待自动重连...")


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def main():
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    log.info(
        "接收端启动 server=%s namespace=%s socketio_path=%s input_dir=%s log_file=%s",
        SERVER_URL,
        NAMESPACE,
        SOCKETIO_PATH,
        INPUT_DIR.resolve(),
        (LOG_DIR / "receiver.log").resolve(),
    )
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
