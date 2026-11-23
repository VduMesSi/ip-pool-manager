# Unified Compose trial

This is a trial deployment entry point only. It does not replace either service image or merge their codebases.

## Existing NAS directories

- IP Pool Manager: `/share/CACHEDEV1_DATA/Container/ip-pool-manager`
- Xray Manager: `/share/CACHEDEV1_DATA/Container/xray-manager`

The project-level `.env` stores these paths and the two existing API tokens. Copy the token values from the current per-service `.env` files; do not generate new tokens during this migration.

## Shared data and service boundaries

Both services mount the existing IP Pool `data/` directory at `/data`. IP Pool Manager mounts it read/write; Xray Manager mounts it read-only. Xray's own config, runtime state, Geo assets, and Xray binary remain in its existing directory.

Both services retain host networking, their existing image repositories, container names, and restart policies. There is intentionally no `depends_on`: the services remain independently startable and restartable.

## Trial procedure

1. Back up both existing service directories and both existing `.env` files.
2. Create a separate Compose project directory on the NAS and copy `docker-compose.unified.yml` there as `docker-compose.yml`.
3. Copy `.env.unified.example` there as `.env`; fill in the existing API token values.
4. Validate with `docker compose config` before stopping either existing project.
5. Stop the old Compose projects before starting the unified project. Both unified services use the same `container_name` values, so the old containers must not still exist.
6. Start with `docker compose up -d`, then verify both services, their ports, mounts, and logs.

Do not run the unified project alongside the old projects: duplicate container names and host-network listeners will conflict. Do not delete or move the existing data, config, Geo, or binary directories.

Rollback: stop the unified project, then start the original Compose projects using their original directories and environment files.
