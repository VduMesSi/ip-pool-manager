# NAS IP Pool Manager

NAS 端 IPv6 地址池管理服务。当前运行模式为两个完全隔离的 IPv6 池：CF1/CF2 专用池（`ipv60`）与其他节点专用池（`ipv6`）。IPv4 不再参与自动扫描调度；原 IPv4 数据目录保留，不删除。

## 双 IPv6 池

每个池分别维护自己的 CIDR 来源、CFST 结果 CSV、动态池状态 JSON 和独立 SQLite 质量/永久库文件。

```text
/data/
  ipv60/
    ipv60.txt
    result_ipv60.csv
    pool_state_ipv60.json
  ipv6/
    ipv6.txt
    result_ipv6.csv
    pool_state_ipv6.json
  quality/ipv60.sqlite3
  quality/ipv6.sqlite3
```

首次启动会自动创建两个空来源文件。请分别将适用于 CF1/CF2 和其他节点的 IPv6 CIDR 写入对应的 `ipv60.txt`、`ipv6.txt`。两个来源文件不可混用。未配置来源时不会启动扫描。\n\n**升级注意：** 旧版本的 `/data/ipv6/` 与新版本其他节点池使用相同路径。新版本会直接读取其中的 `ipv6.txt`、`result_ipv6.csv` 和 `pool_state_ipv6.json`，不会自动迁移、清空或重命名。因此升级前必须备份并检查旧目录；如果旧文件属于 CF1/CF2，不能原样留在 `/data/ipv6/`，应在确认内容后再分别迁移到 `/data/ipv60/`。旧 `/data/quality/ip_quality.sqlite3` 也会保留，但不会自动拆分迁移到两个新质量库。`/data/ipv4/` 仅作为历史数据保留，不参与新调度。

## 扫描策略

- 每轮最多扫描 3000 个 IPv6 地址，两个池各分配最多 1500 个；若其中一个池地址不足，另一池可补足总量上限。
- 每批最多 300 个地址，两个池交替执行。
- CFST 并发 20，TCPing 4 次，延迟上限 120ms，零丢包过滤，不执行下载测速。
- 批次间隔 300 秒（5 分钟）。
- 每批开始前检查三个 TCP/443 目标，至少两个可达即通过；失败时最多重试三轮。
- CFST 退出码为 0 且未生成 CSV，视为本批零合格地址：不报错、不清空已有结果、不写入伪造质量记录，扫描继续。
- 两个池使用独立 SQLite 文件；永久资格按连续 7 个自然日、每日平均延迟低于 80ms 且零丢包判断。

## API

所有 `/api/v1/` 接口需要 `Authorization: Bearer <IP_POOL_API_TOKEN>`。

- `GET /api/v1/status`
- `GET /api/v1/ipv60/pool`、`GET /api/v1/ipv6/pool`
- `POST /api/v1/scan-cycle`
- 两个池均支持原有的 `/{family}/scan`、`refresh`、`scan-refresh`、`result` 接口。
- `/api/v1/ipv6/pool` 对应其他节点池；`/api/v1/ipv60/pool` 对应 CF1/CF2 专用池。

## 部署

保留 NAS 上现有 `data/` 和 `bin/` 挂载。先备份 `data/`，创建两个来源文件并填入各自 CIDR，再拉取新镜像。不要删除旧的 IPv4 目录。旧 IPv6 目录必须先备份并核对内容，确认归属后再部署，避免把 CF1/CF2 的旧数据误当成其他节点数据。
