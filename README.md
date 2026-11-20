# NAS IP Pool Manager

NAS 端 IPv6 地址池管理服务。当前运行模式为两个完全隔离的 IPv6 池：CF1/CF2 专用池（`ipv6_cf`）与其他节点专用池（`ipv6_other`）。IPv4 不再参与自动扫描调度；原 IPv4 数据目录保留，不删除。

## 双 IPv6 池

每个池分别维护自己的 CIDR 来源、CFST 结果 CSV、动态池状态 JSON 和 SQLite 质量历史（以 family 字段隔离）。

```text
/data/
  ipv6_cf/
    ipv6_cf.txt
    result_ipv6_cf.csv
    pool_state_ipv6_cf.json
  ipv6_other/
    ipv6_other.txt
    result_ipv6_other.csv
    pool_state_ipv6_other.json
  quality/ip_quality.sqlite3
```

请分别将适用于 CF1/CF2 和其他节点的 IPv6 CIDR 写入对应的 `ipv6_cf.txt`、`ipv6_other.txt`。两个来源文件不可混用。旧的 `/data/ipv6` 目录不会自动迁移或删除。

## 扫描策略

- 每轮最多扫描 3000 个 IPv6 地址，两个池各分配最多 1500 个；若其中一个池地址不足，另一池可补足总量上限。
- 每批最多 300 个地址，两个池交替执行。
- CFST 并发 20，TCPing 4 次，延迟上限 120ms，零丢包过滤，不执行下载测速。
- 批次间隔 60 秒（当前测试配置）。
- 每批开始前检查三个 TCP/443 目标，至少两个可达即通过；失败时最多重试三轮。
- CFST 退出码为 0 且未生成 CSV，视为本批零合格地址：不报错、不清空已有结果、不写入伪造质量记录，扫描继续。
- 每个地址族/用途使用同一 SQLite 文件中的独立 family 键；永久资格按连续 7 个自然日、每日平均延迟低于 80ms 且零丢包判断。

## API

所有 `/api/v1/` 接口需要 `Authorization: Bearer <IP_POOL_API_TOKEN>`。

- `GET /api/v1/status`
- `GET /api/v1/ipv6_cf/pool`、`GET /api/v1/ipv6_other/pool`
- `POST /api/v1/scan-cycle`
- 两个池均支持原有的 `/{family}/scan`、`refresh`、`scan-refresh`、`result` 接口。
- 为兼容旧客户端，`/api/v1/ipv6/pool` 及旧 IPv6 操作路径映射到 CF1/CF2 池。

## 部署

保留 NAS 上现有 `data/` 和 `bin/` 挂载。先备份 `data/`，创建两个来源文件并填入各自 CIDR，再拉取新镜像。不要删除旧的 IPv4/IPv6 目录。
