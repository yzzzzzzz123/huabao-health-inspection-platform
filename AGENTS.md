# 华宝健康巡检平台仓库约定

## Git 与目录边界

- `huabao-health-inspection-platform` 是唯一 Git 根。`huabao-dolphin-skills/` 与
  `huabao-worktree-server/` 是同一仓库中的两个组件目录，不得在组件目录内再次
  `git init`，也不得恢复嵌套 `.git` 或改成 submodule。
- 所有源码修改、快照、提交、分支与 linked worktree 操作都以父根为仓库根。
  `huabao-new-energy-ai-growth-copilot` 是迁移来源，只读保留，不得修改或作为运行时
  fallback。
- 每日身份固定使用父根下的 `worktrees/YYYY-MM-DD`、分支
  `run/health-inspection/daily/YYYY-MM-DD` 与运行 ID `hi-YYYY-MM-DD`。每日 linked
  worktree 必须是完整 monorepo snapshot，同时包含两个组件，而不是只复制 Server。

## 组件与部署边界

- `huabao-dolphin-skills/` 负责 Agent、任务书、提示词、Schema、业务 Python 与
  Dolphin Workflow。发布时可以只把该目录构建为版本化 bundle 上传到 AI 平台。
- `huabao-worktree-server/` 负责 HTML、Workspace API、Git worktree、SQLite、归档、
  调度与安全边界。它可以作为独立服务进程部署，但部署主机必须保留完整 monorepo
  checkout 或受控 mirror；只有完整仓库才能创建包含两组件的日期 linked worktree。
- “独立部署”不等于“独立 Git 根”。跨组件合同变更应在同一个 monorepo commit 中
  同步完成，Server-only 或 Dolphin-only 修改仍应遵守各自组件边界。

## 运行态与秘密

- Git common-dir 状态只写父根 `.huabao/`；日期 worktree 只写父根
  `worktrees/`；完成态业务归档只写父根 `history/`。这些目录的业务内容、`.runtime/`、
  SQLite、缓存、虚拟环境与真实凭据不得进入 Git。
- 唯一允许跟踪的 `.env` 是
  `huabao-worktree-server/shared/.env`，且只能保存无密钥合同与空 secret 占位。
  token、secret、webhook、手机号、代理凭据、证书和机器私有路径不得提交。
- `history/` 只保留受控业务归档，不复制公共源码、依赖、Git 数据或运行缓存。

## 修改与验证

- 不创建 `tests/` 或 Test Agent；需要夹具时使用系统临时目录。
- Python 与 Git 子进程使用 direct argv / `shell=False`，不得用 shell wrapper 解释配置。
- Server 修改后至少运行 compileall、`server.py config`、`worktree_cli.py list`、
  `state_store_cli.py integrity`；Dolphin 修改后至少运行 compileall、
  `orchestrator_cli.py config`、release 校验与 Skill quick validation；最终执行
  `git diff --check`。
- 涉及运行链路时，使用新业务日期完成 Stage 0～5，并核对日期 worktree 同时包含两个
  组件、artifact 哈希、恢复边界、完成态 Git clean 与级联删除无残留。
