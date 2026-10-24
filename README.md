# Ghostkey — ByteSentinels

Everything the team needs is in **CLAUDE.md** (contracts, rules, ownership, expected demo results).
Claude Code reads it automatically when you run `claude` in this folder.

Quick start:
1. `cp .env.example .env`
2. `docker compose pull && docker compose up -d --build`
3. Work without the gateway: `docker compose run --rm core python -m fixtures.load_fixtures --reset`
4. Dashboard: http://localhost:8501
