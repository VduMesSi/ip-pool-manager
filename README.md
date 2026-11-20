# NAS IP Pool Manager

NAS 端 Cloudflare IP 池管理服务。CFST 负责 TCPing 延迟/丢包测试；本项目负责抽样、低并发分批、IPv4/IPv6 交替调度、质量历史、永久 IP 资格判定和动态池刷新。

## 扫描策略（0.4.0）

- 每轮 IPv4 + IPv6 合计最多 3000 个地址，默认两种协议各 1500 个。
- 每批最多 300 个地址，IPv4/IPv6 交替执行，默认 10 批。
- CFST 并发固定为 20，单地址 TCPing 4 次；使用 `-dd` 禁止大批量下载测速。
- 每批完成后等待 10 分钟再启动下一批；前一轮未结束时不叠加新轮次。
- 自动调度：Asia/Taipei 每日 07:30、13:30、19:30。
- 每批前后检查 NAS 外网 TCP 443 连通性；检测失败即停止本轮剩余批次。
- CFST 测试结果写入每日质量历史。IP 连续 7 个自然日每天至少有一次有效记录、当日平均延迟严格低于 80ms、且记录的最大丢包率为 0，才取得永久库资格。
- 永久库保留历史记录；资格暂时失效只标记为 historical，不删除 IP 历史。
- 每轮结束后把永久库有效地址并入原 CFST 结果，再调用既有动态池 refresh 逻辑。

注意：这里的延迟是 CFST TCP connect latency，不是 ICMP ping。每日三轮扫描只会更新同一个自然日的统计，不会算成三天。永久库的 7 天资格需要连续自然日数据；缺测一天即不满足连续资格。

## 部署

NAS 目录建议：

```text
ip-pool/
├── docker-compose.yml
├── .env
├── bin/CloudflareST
└── data/
    ├── ipv4/ipv4.txt
    ├── ipv6/ipv6.txt
    ├── ipv4/pool_state_ipv4.json
    ├── ipv6/pool_state_ipv6.json
    └── quality/ip_quality.sqlite3
```

CFST 可执行文件必须是与 NAS 架构匹配的 Linux 版本，并放在 `bin/CloudflareST`。源文件每行可以是 IP 或 CIDR；程序按地址族校验并抽样。建议先确认实际 CFST 版本支持输入文件中的单个 IPv4/IPv6 地址行。

首次部署：

```bash
cp .env.example .env
# 设置 IP_POOL_API_TOKEN
docker compose pull
docker compose up -d
```

更新：

```bash
docker compose pull
docker compose up -d
```

数据均保存在挂载的 `data/` 中，更新镜像不会清除。

## API

所有 `/api/v1/` 接口需要请求头 `Authorization: Bearer <IP_POOL_API_TOKEN>`。

- `GET /health`
- `GET /api/v1/status`
- `GET /api/v1/ipv4/pool`
- `GET /api/v1/ipv6/pool`
- `POST /api/v1/scan-cycle`：手动触发完整分批轮次（耗时较长）
- 原有 `POST /api/v1/{family}/scan`、`refresh`、`scan-refresh`、`result` 接口保留。

示例：

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://192.168.2.222:8088/health
```

## 重要运行说明

- `POST /api/v1/scan-cycle` 是同步等待完整轮次的接口，建议仅用于手动测试；正常使用由每日调度器执行。
- 批次按上一批完成后等待 10 分钟，因此整轮耗时会明显超过 90 分钟（还需加上每批测速时间）。
- 外网保护使用两个公共 IPv4 地址的 TCP 443 连通性检查。它能检测部分断网情形，但不能保证识别路由器所有异常，也不能替代路由器 CPU、conntrack 和 WAN 状态监控。
- 动态池状态文件与 SQLite 质量库相互独立。请定期备份整个 `data/` 目录。
- 当前流程只做 TCPing 延迟/丢包，不对 3000 个地址进行下载测速。下载测速可在候选缩小后另行执行。
