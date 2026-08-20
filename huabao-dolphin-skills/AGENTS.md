# Dolphin 业务组件约定

本组件只维护华宝新能站内健康巡检的 Agent、任务书、提示词、Schema、业务 Python
与 Dolphin Workflow。固定范围为 Asia/Shanghai、CNY，以及流量、转化、商品三个
健康维度和 37 项指标。

源码属于父级 `huabao-health-inspection-platform` 单一 Git 根，本目录不是嵌套仓库。
它可以作为独立版本化 bundle 上传 Dolphin/AI 平台，但 Server 部署必须保留完整
monorepo checkout，且每日 linked worktree 必须同时包含 Dolphin 与 Server 组件。

所有日期工作区内容只能通过 Worktree Server 的 Workspace API 使用合同 artifact ID
读写。业务代码不得接受任意服务器路径，不得直接访问 Git、linked worktree、SQLite、
归档目录、调度器、运行环境管理或通知适配器。

`data_layer_health_policy` 必须由 Worktree Server 在创建 workspace 时依据已发布版本
写入。Dolphin 在任何任务书或 Stage 写入前只读该 artifact，并同时校验 artifact 字节
哈希、不可变发布版本 `published_sha256` 和完整运行政策 `sha256`；缺失或不一致立即
失败关闭。Dolphin 与 fixture 均不得构造、回退或上传默认 v1.0 政策。

固定只有七个 Agent：总控、数据、巡检、诊断、建议、审核、报告。Stage 0 只调度
白名单确定性数据步骤；Stage 1 至 5 输出 business 与 intelligence 双投影，经过中央
Schema 和语义门禁后才能晋升。成功产物不可覆盖，同一 Stage 最多三个业务 attempt。

Reporter 只声明固定 delivery_request，不持有 webhook、token、secret 或网络投递
能力。完成态封存、清单校验和实际通知属于 Worktree Server。

生产后端只接受 Dolphin 托管 Agent 响应；fixture 后端仅用于本地 E2E，不得作为
生产模型结果。Python 要求 3.11 及以上，正式运行 stdlib-only。
