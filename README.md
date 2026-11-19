# NAS IP Pool Manager

第一阶段：将 IPv4 / IPv6 IP 库和 IP 池优选服务迁移到 Docker。此阶段不启动 Xray、不执行 outbound 轮回，也不替换现有 Windows Manager。

## GitHub 镜像构建

本仓库使用 GitHub Actions 自动构建并发布 GHCR 镜像：

`ghcr.io/vdumessi/ip-pool-manager:latest`

触发方式：
- 推送到 `main`：构建并更新 `latest`。
- 推送 `v*` 标签（例如 `v0.1.0`）：额外发布对应版本标签。
- Actions 页面手动运行：`workflow_dispatch`。

仓库需要启用 Actions。工作流通过 GitHub 自动提供的 `GITHUB_TOKEN` 发布包，不需要另建 PAT。首次发布后，如需 NAS 匿名拉取，请在 GitHub Packages 的 Package settings 中将包可见性设为 Public。

## NAS 目录

建议在 QNAP 建立：

```text
/share/CACHEDEV1_DATA/Container/ip-pool/
├── docker-compose.yml
├── .env
├── bin/
│   └── CloudflareST
└── data/
    ├── ipv4/
    │   └── ipv4.txt
    ├── ipv6/
    │   └── ipv6.txt
    └── logs/
```

`bin/CloudflareST` 必须是与 NAS CPU 架构匹配的 Linux 可执行文件。先在 NAS 执行 `uname -m` 确认架构。本工作流当前构建 `linux/amd64` 镜像，适用于 x86_64/amd64 NAS。

## 首次部署

1. 将 `docker-compose.yml` 放入上述目录。
2. 建立 `bin/`、`data/ipv4/`、`data/ipv6/`、`data/logs/`。
3. 将匹配架构的 CFST 程序放入 `bin/CloudflareST`，并确保可执行权限。
4. 将 IPv4 源文件放入 `data/ipv4/ipv4.txt`，IPv6 源文件放入 `data/ipv6/ipv6.txt`。
5. 从 `.env.example` 复制生成 `.env`，设置至少 32 字符的随机 `IP_POOL_API_TOKEN`。
6. 检查 `docker-compose.yml` 中的 NAS IP `192.168.2.222` 是否正确。
7. 执行：

```bash
docker compose pull
docker compose up -d
```

查看状态：

```bash
docker compose ps
docker compose logs --tail=100 -f
```

## 更新镜像

```bash
docker compose pull
docker compose up -d
```

IP 库、测速结果和池状态都保存在 NAS 的 `data/` 目录，不会随镜像更新而删除。

## API

所有 `/api/v1/` 接口需要请求头：

`Authorization: Bearer <IP_POOL_API_TOKEN>`

- `GET /health`
- `GET /api/v1/status`
- `GET /api/v1/ipv4/pool`
- `GET /api/v1/ipv6/pool`
- `POST /api/v1/ipv4/scan`
- `POST /api/v1/ipv6/scan`
- `POST /api/v1/ipv4/refresh`
- `POST /api/v1/ipv6/refresh`
- `POST /api/v1/ipv4/scan-refresh`
- `POST /api/v1/ipv6/scan-refresh`

示例：

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://192.168.2.222:8088/api/v1/status
```

## 持久化文件

- `data/ipv4/ipv4.txt`
- `data/ipv4/result_ipv4.csv`
- `data/ipv4/pool_state_ipv4.json`
- `data/ipv6/ipv6.txt`
- `data/ipv6/result_ipv6.csv`
- `data/ipv6/pool_state_ipv6.json`

## 当前版本限制与验证事项

- 这是原 v0.1 代码的 GHCR 部署整理版，不代表已经完成 NAS 实机验证。
- CFST 命令行参数、实际输出文件名及 CSV 第 5 列延迟字段，仍需用你实际使用的 Linux CFST 版本验证。
- 目前是手动 API 触发扫描/刷新，没有后台定时任务。
- 尚未实现 Windows GUI、Xray 配置应用、outbound 分配及轮回调度。
- `/api/v1/{family}/result` 是预留的结果回传接口；当前阶段没有 Xray 实际代理验证端。
- 不要将 API 端口直接暴露到公网。
