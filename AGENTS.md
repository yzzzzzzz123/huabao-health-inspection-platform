# 华宝健康巡检平台仓库约定

## Git 与目录边界

- `huabao-health-inspection-platform` 是唯一 Git 根。`huabao-dolphin-skills/` 与
  `huabao-worktree-server/` 是同一仓库中的两个组件目录，不得在组件目录内再次
  `git init`，也不得恢复嵌套 `.git` 或改成 submodule。
- 所有源码修改、快照、提交、分支与 linked worktree 操作都以父根为仓库根。
  `huabao-new-energy-ai-growth-copilot` 是迁移来源，只读保留，不得修改或作为运行时
  fallback。
- 每日身份固定使用 Server 所属的
  `huabao-worktree-server/worktrees/YYYY-MM-DD`、分支
  `run/health-inspection/daily/YYYY-MM-DD` 与运行 ID `hi-YYYY-MM-DD`。虽然物理目录位于
  Server 组件下，但该日期目录本身必须是父仓的 linked worktree 根，是包含两个组件的
  完整 monorepo snapshot，不是 Server 子树的副本或第二个 Git 仓库。

## 组件与部署边界

- `huabao-dolphin-skills/` 负责 Agent、任务书、提示词、Schema、业务 Python 与
  Dolphin Workflow。发布时可以只把该目录构建为版本化 bundle 上传到 AI 平台。
- `huabao-worktree-server/` 负责 HTML、Workspace API、Git worktree、SQLite、归档、
  调度与安全边界。它可以作为独立服务进程部署，但部署主机必须保留完整 monorepo
  checkout 或受控 mirror；只有完整仓库才能创建包含两组件的日期 linked worktree。
- “独立部署”不等于“独立 Git 根”。跨组件合同变更应在同一个 monorepo commit 中
  同步完成，Server-only 或 Dolphin-only 修改仍应遵守各自组件边界。

## Server 运行态与秘密

- 父根只承担唯一 Git 根职责。Git 对象、refs、worktree 注册和 common dir 仍属于父仓
  `.git`；业务控制态只写 `huabao-worktree-server/.huabao/`，日期 linked worktree
  只写 `huabao-worktree-server/worktrees/`，完成态业务归档只写
  `huabao-worktree-server/history/`。不得在父根恢复同名运行目录，也不得把父根旧路径
  作为 fallback。
- 日期运行的 `.runtime/`、`input/`、`context/` 与 `result/` 位于日期 linked worktree
  根，例如 `huabao-worktree-server/worktrees/YYYY-MM-DD/.runtime/`；它们不再额外嵌入
  该快照中的 `huabao-worktree-server/` 组件目录。
- 从旧父根布局升级时必须先停服，再通过受控迁移把父根 `.huabao/` 中的 SQLite 与路径
  绑定迁入 Server 所属 `.huabao/`，完成完整性和路径重映射校验后才可启动新代码。
  旧、新位置同时存在有效状态时必须 fail closed；不得静默选择一侧、合并两库或以空库
  覆盖既有运行、政策、认领及投递门禁事实。
- 上述运行目录的业务内容、SQLite、缓存、虚拟环境与真实凭据不得进入 Git。
- 唯一允许跟踪的 `.env` 是
  `huabao-worktree-server/shared/.env`，且只能保存无密钥合同与空 secret 占位。
  token、secret、webhook、手机号、代理凭据、证书和机器私有路径不得提交。
- `huabao-worktree-server/history/` 只保留受控业务归档，不复制公共源码、依赖、Git
  数据或运行缓存。

## 修改与验证

- 不创建 `tests/` 或 Test Agent；需要夹具时使用系统临时目录。
- Python 与 Git 子进程使用 direct argv / `shell=False`，不得用 shell wrapper 解释配置。
- Server 修改后至少运行 compileall、`server.py config`、`worktree_cli.py list`、
  `state_store_cli.py integrity`；Dolphin 修改后至少运行 compileall、
  `orchestrator_cli.py config`、release 校验与 Skill quick validation；最终执行
  `git diff --check`。
- 涉及运行链路时，使用新业务日期完成 Stage 0～5，并核对日期 worktree 同时包含两个
  组件，且只在 Server 所属运行根留下控制态、worktree 与归档；同时核对 artifact
  哈希、恢复边界、完成态 Git clean 与级联删除无残留。
