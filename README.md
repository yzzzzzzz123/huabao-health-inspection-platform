# 华宝健康巡检平台

本项目采用一个 Git 仓库、两个可独立部署组件。单一仓库保证源码版本、政策合同、
Workspace API 与每日 Git snapshot 原子绑定；部署时仍可分别把 Dolphin bundle 上传到
AI 平台、把 Worktree Server 作为服务运行。

```text
huabao-health-inspection-platform/       # 唯一 Git 根
├─ huabao-dolphin-skills/                # AI 平台业务 bundle
├─ huabao-worktree-server/               # 服务端与 HTML 工作台
├─ worktrees/YYYY-MM-DD/                 # 完整 monorepo linked worktree
├─ history/YYYY-MM-DD/                   # 完成态业务归档
└─ .huabao/                              # Git common-dir 控制面状态
```

## 部署模型

`huabao-dolphin-skills/` 包含 7 个 Agent、任务书、提示词、Schema、业务 Python 与
Stage 0～5 Workflow。它可从固定 Git snapshot 单独打包并上传 Dolphin/AI 平台，bundle
版本与 SHA-256 必须由 Server 绑定。

`huabao-worktree-server/` 包含 HTML 工作台、Workspace API、SQLite、调度、封存、归档、
删除与安全门禁。Server 是独立部署单元，但不是独立源码仓库：服务器主机必须部署完整
monorepo checkout 或受控 mirror，并从其中启动 Server。若只复制
`huabao-worktree-server/`，服务应 fail closed，因为它无法生成包含两个组件的完整日期
linked worktree。

全新部署只初始化 37 项固定指标目录和一个未发布草稿，所有指标阈值均为空；系统不会
内置或自动发布 `v1.0`。管理员必须在工作台完成配置并主动发布首个版本，此前任何新
巡检都在创建记录和 worktree 前失败关闭，Dolphin 也不会提供默认政策。

每次新建运行时，Server 从父 Git 根构建隔离 snapshot，并在
`worktrees/YYYY-MM-DD` 创建 linked worktree。该目录天然包含
`huabao-dolphin-skills/` 与 `huabao-worktree-server/` 的同一提交视图；运行期只在合同允许
的 `input/`、`context/`、`result/` 与忽略的 `.runtime/` 中写入数据。

## 本地入口

从 Server 组件目录启动工作台与 API：

```text
cd huabao-worktree-server
python -I skills/health-inspection/scripts/server.py serve
```

从 Dolphin 组件目录检查或运行 bundle：

```text
cd huabao-dolphin-skills
python -I skills/health-inspection/scripts/orchestrator_cli.py config
python -I skills/health-inspection/scripts/orchestrator_cli.py release
```

组件的完整运行、API 和安全合同分别见
`huabao-worktree-server/README.md` 与 `huabao-dolphin-skills/README.md`。

## 运行数据边界

- `.huabao/`、`.runtime/`、`worktrees/*` 与 `history/*` 是机器运行态或业务归档，均由
  父根 `.gitignore` 排除；`worktrees/.gitkeep` 和 `history/.gitkeep` 只保留目录结构。
- SQLite/WAL/SHM、虚拟环境、缓存、日志与真实凭据不进入 Git。
- 唯一允许跟踪的环境合同是
  `huabao-worktree-server/shared/.env`，其中不得出现真实 token 或 secret。

## 历史迁移说明

两个原独立仓库使用未 squash 的 subtree merge 导入，因此原提交对象与 commit ID 均
保留并可达。Dolphin 导入时原 HEAD 为
`854f02e42d26e2eb0115f23179b21cc8f78dc339`，Server 原 HEAD 为
`88179ee97bdef93f4199fbfbc57b14bdf66f5eb7`。

导入前的文件位于各自历史的仓库根，导入后的文件位于组件前缀下；subtree merge 不会
把这次路径变化记录成逐文件 rename。因此普通的
`git log -- huabao-worktree-server/README.md` 只展示前缀路径阶段。查看完整旧历史时应从
原 HEAD 使用原根路径，例如：

```text
git log 88179ee97bdef93f4199fbfbc57b14bdf66f5eb7 -- README.md
git log 854f02e42d26e2eb0115f23179b21cc8f78dc339 -- README.md
```

迁移来源项目保持只读，不是当前运行依赖。
