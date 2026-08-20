# Dolphin Agent 编排合同

## 运行边界

Dolphin 只负责任务书、Agent 推理、确定性业务计算、Schema 与语义校验、渲染和
Workflow。所有日期工作区读写都通过 Workspace API 的 artifact ID 完成。Dolphin
不得接收任意服务器路径、存储句柄、宿主凭据或通知端点，也不得直接控制服务器的
版本库、数据库、归档和调度设施。

工作区创建后，以服务器响应中的 run_id、business_date、incarnation_id、
platform_release_sha256、严格七字段 platform_release 和 workspace_version=2.0 为
权威绑定。后续请求必须同时携带 incarnation 与 release SHA 请求头。PUT 使用原始
字节、Content-Type、X-Content-SHA256 和 If-None-Match: *；相同字节重放幂等，
不同字节重放失败关闭。

## 七个 Agent

1. orchestrator_agent：接受运行绑定，按门禁推进 Stage 0～5，确认最终交付。
2. data_operator_agent：调度受控数据步骤并核验 37 项输出，不改写经营数字。
3. inspector_agent：把全部确定性异常严格分区为调查 case。
4. diagnostician_agent：比较竞争假设，标注证据边界和根因置信度。
5. advisor_agent：生成 review_only 或 manual_adjustment 建议。
6. auditor_agent：审核异常、诊断、建议与到期回看之间的逻辑闭合。
7. reporter_agent：形成管理日报并声明固定投递意图，不执行投递。

Validator、Runner、Worker 与 Workspace API 都是确定性组件，不计为 Agent。

## Stage 门禁

Stage 0 依次执行 data_layer、calculate、detect、validate。指标 ID 和顺序必须与
metric_catalog.json 完全一致，集合恰为 37 项；runtime policy 必须绑定目录的规范
清单哈希。来源工作簿 SHA 只作为来源元数据，不要求运行环境存在工作簿。

Stage 1 的 cases[].anomaly_ids 必须严格分区本期全部异常：不遗漏、不重复、不增加，
并通过名为 case_anomaly_partition_contract 的自测。

Stage 2 必须提出并检验竞争假设。证据不足时保留不确定性，不能把相关性写成因果。

Stage 3 的 action_type 只能为 review_only 或 manual_adjustment。后者必须闭合异常、
诊断、指标、具体调整、预期方向和验收标准；系统不审批也不执行调整。

Stage 4 必须覆盖全部建议，并只解释 packet 中明确给出的到期异常回看。回看变化不得
直接归因于建议或人工动作。

Stage 5 只能推荐审核支持的建议。delivery_request 为固定三字段受控投影，Reporter
只声明意图；服务器在封存后决定实际投递。

所有 Stage 都必须通过中央 Schema、跨阶段 ID、证据引用、语义与自测门禁。自测状态
必须为 passed，所有检查必须通过，unresolved_issues 必须为空。

## 尝试与恢复

每个 Stage 最多三个业务 attempt，编号固定为 001～003。每次尝试保存 request、
response_raw、attempt、events、cli 和 artifacts 投影。失败尝试同样持久化；恢复时先
读取并校验已有字节与哈希，再补全同一尝试或进入下一尝试。成功 Stage 不可覆盖。

--stop-after 在指定 Stage 正式产物上传后返回开放状态。--resume 必须复用同一 run 与
incarnation，从已验证产物后的下一 Stage 继续。finalize 使用 platform_release.bound_at
作为确定性时间来源；任意中断点恢复都应对已有投影做同字节确认，不生成漂移内容。

## 最终封存

bootstrap 必须写入受控 orchestrator_thread 投影，包含运行绑定、backend 与稳定
thread_id，但不含凭据。finalize 生成 intelligence ledger、execution ledger、UI 安全
投影、memory、events、action note 投影、log summary 和 delivery manifest。

delivery manifest 顶层必须绑定 run_id、business_date、incarnation_id、
platform_release_sha256 及服务器返回的严格七字段 platform_release。seal 使用已上传
manifest 实际字节的 SHA-256。workspace index 与 archive manifest 由服务器生成，
Dolphin 不写入。

## Backend

生产 backend 只接受 Dolphin 托管执行返回的结构化响应。本地 fixture backend 必须由
明确参数启用，只用于 E2E 和恢复验证，不得作为生产推理来源。
