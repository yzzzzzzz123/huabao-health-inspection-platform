# Dolphin 业务根约定

本仓只维护华宝新能站内健康巡检的 Agent、任务书、提示词、Schema、业务 Python
与 Dolphin Workflow。固定范围为 Asia/Shanghai、CNY，以及流量、转化、商品三个
健康维度和 37 项指标。

所有日期工作区内容只能通过 Worktree Server 的 Workspace API 使用合同 artifact ID
读写。业务代码不得接受任意服务器路径，不得直接访问 Git、linked worktree、SQLite、
归档目录、调度器、运行环境管理或通知适配器。

固定只有七个 Agent：总控、数据、巡检、诊断、建议、审核、报告。Stage 0 只调度
白名单确定性数据步骤；Stage 1 至 5 输出 business 与 intelligence 双投影，经过中央
Schema 和语义门禁后才能晋升。成功产物不可覆盖，同一 Stage 最多三个业务 attempt。

Reporter 只声明固定 delivery_request，不持有 webhook、token、secret 或网络投递
能力。完成态封存、清单校验和实际通知属于 Worktree Server。

生产后端只接受 Dolphin 托管 Agent 响应；fixture 后端仅用于本地 E2E，不得作为
生产模型结果。Python 要求 3.11 及以上，正式运行 stdlib-only。
