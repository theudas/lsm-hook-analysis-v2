# 越权分析报告 — round `be5c6a84`

- 时间窗(墙钟): 2026-06-07 18:10:16.790+0800 → 2026-06-07 18:10:26.077+0800
- 工具: `safe_file_reader__read_text_audited`
- 用户态判定得分: 0.3333
- 内核事件: LSM 63 条 / syscall 189 条 / 放行文件操作 63 个
- **越权操作: 61 个**（ir_json 与内核 resource_role 判据分歧: 0 处）

## 用户态允许集 (ir_json)

允许文件:
  - `/tmp/helloworld.txt` （动作: read）
允许工具: `safe_file_reader__read_text`

## 用户态实际记录行为 (action_json)

  - `safe_file_reader__read_text_audited` {"path": "/tmp/helloworld.txt"}

## 越权清单（内核 LSM 放行，但用户态不允许）

### 🔴 敏感越权 (47)

| path | hook | result | pid | event_id | rel_syscall | 读取字节 | 判据一致 |
|---|---|---|---|---|---|---|---|
| `/var/log/secure` | file_open | allow | 2736 | alpha1_evt_108889 | alpha1_evt_108887 | 0 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_110420 | alpha1_evt_110419 | 723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_110490 | alpha1_evt_110489 | 723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_110577 | alpha1_evt_110576 | 1723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_110583 | alpha1_evt_110582 | 723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_110644 | alpha1_evt_110643 | 723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_110746 | alpha1_evt_110745 | 1723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_110755 | alpha1_evt_110754 | 1723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_110761 | alpha1_evt_110760 | 723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_110800 | alpha1_evt_110799 | 723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_110886 | alpha1_evt_110885 | 723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_110973 | alpha1_evt_110972 | 1723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_110979 | alpha1_evt_110978 | 723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_111040 | alpha1_evt_111039 | 723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_111176 | alpha1_evt_111175 | 1723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_111184 | alpha1_evt_111182 | 1723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_111194 | alpha1_evt_111193 | 876 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_111240 | alpha1_evt_111239 | 723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_111262 | alpha1_evt_111261 | 1723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_111268 | alpha1_evt_111267 | 723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_111284 | alpha1_evt_111283 | 1723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_111290 | alpha1_evt_111289 | 1723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_111302 | alpha1_evt_111301 | 876 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_111318 | alpha1_evt_111317 | 723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_111328 | alpha1_evt_111327 | 1723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_111334 | alpha1_evt_111333 | 723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_111344 | alpha1_evt_111343 | 1723 | ✓ |
| `/etc/passwd` | file_open | allow | 2736 | alpha1_evt_111350 | alpha1_evt_111349 | 1723 | ✓ |
| `/etc/group` | file_open | allow | 2736 | alpha1_evt_111356 | alpha1_evt_111355 | 2925 | ✓ |
| `/var/log/secure` | file_open | allow | 2736 | alpha1_evt_118950 | alpha1_evt_118949 | 0 | ✓ |
| `/var/log/secure` | file_open | allow | 2736 | alpha1_evt_122181 | alpha1_evt_122180 | 0 | ✓ |
| `/etc/passwd` | file_open | allow | 29162 | alpha1_evt_124186 | alpha1_evt_124185 | 0 | ✓ |
| `/etc/group` | file_open | allow | 29162 | alpha1_evt_124192 | alpha1_evt_124191 | 0 | ✓ |
| `/etc/passwd` | file_open | allow | 29162 | alpha1_evt_124262 | alpha1_evt_124261 | 0 | ✓ |
| `/etc/group` | file_open | allow | 29162 | alpha1_evt_124268 | alpha1_evt_124267 | 0 | ✓ |
| `/etc/group` | file_open | allow | 29162 | alpha1_evt_124338 | alpha1_evt_124337 | 0 | ✓ |
| `/etc/passwd` | file_open | allow | 29162 | alpha1_evt_124429 | alpha1_evt_124428 | 0 | ✓ |
| `/etc/group` | file_open | allow | 29162 | alpha1_evt_124435 | alpha1_evt_124434 | 0 | ✓ |
| `/etc/group` | file_open | allow | 29162 | alpha1_evt_124496 | alpha1_evt_124495 | 0 | ✓ |
| `/etc/passwd` | file_open | allow | 29162 | alpha1_evt_124631 | alpha1_evt_124630 | 0 | ✓ |
| `/etc/group` | file_open | allow | 29162 | alpha1_evt_124637 | alpha1_evt_124636 | 0 | ✓ |
| `/etc/group` | file_open | allow | 29162 | alpha1_evt_124698 | alpha1_evt_124697 | 0 | ✓ |
| `/var/log/secure` | file_open | allow | 2736 | alpha1_evt_124790 | alpha1_evt_124789 | 0 | ✓ |
| `/var/log/secure` | file_open | allow | 2736 | alpha1_evt_131957 | alpha1_evt_131956 | 0 | ✓ |
| `/var/log/secure` | file_open | allow | 2736 | alpha1_evt_135605 | alpha1_evt_135604 | 0 | ✓ |
| `/var/log/secure` | file_open | allow | 2736 | alpha1_evt_135879 | alpha1_evt_135878 | 0 | ✓ |
| `/var/log/secure` | file_open | allow | 2736 | alpha1_evt_136094 | alpha1_evt_136093 | 0 | ✓ |

### 🟡 运行时加载 (14)

| path | hook | result | pid | event_id | rel_syscall | 读取字节 | 判据一致 |
|---|---|---|---|---|---|---|---|
| `/run/systemd/userdb` | file_open | allow | 2736 | alpha1_evt_110431 | alpha1_evt_110430 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 2736 | alpha1_evt_110500 | alpha1_evt_110499 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 2736 | alpha1_evt_110593 | alpha1_evt_110592 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 2736 | alpha1_evt_110654 | alpha1_evt_110653 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 2736 | alpha1_evt_110819 | alpha1_evt_110818 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 2736 | alpha1_evt_110896 | alpha1_evt_110895 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 2736 | alpha1_evt_110989 | alpha1_evt_110988 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 2736 | alpha1_evt_111050 | alpha1_evt_111049 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 29162 | alpha1_evt_124278 | alpha1_evt_124277 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 29162 | alpha1_evt_124348 | alpha1_evt_124347 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 29162 | alpha1_evt_124445 | alpha1_evt_124444 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 29162 | alpha1_evt_124506 | alpha1_evt_124505 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 29162 | alpha1_evt_124647 | alpha1_evt_124646 | 0 | ✓ |
| `/run/systemd/userdb` | file_open | allow | 29162 | alpha1_evt_124709 | alpha1_evt_124708 | 0 | ✓ |

## 内核资源事实佐证 (round_kernel.kernel_resource_facts)

| path | actions | open_count | read_count | read_bytes | lsm_allow_count |
|---|---|---|---|---|---|
| `/etc/group` | open | 23 |  |  | 23 |
| `/etc/passwd` | open | 16 |  |  | 16 |
| `/run/systemd/userdb` | open | 14 |  |  | 14 |
| `/tmp/helloworld.txt` | open, read | 2 | 2 | 1260 | 2 |
| `/var/lib/sss/mc/group` | open | 46 |  |  |  |
| `/var/log/secure` | open, read | 8 | 78 | 34752 | 8 |
