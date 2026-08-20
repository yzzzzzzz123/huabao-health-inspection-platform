---
name: health-inspection
description: Run or resume Huabao New Energy's fixed-scope site health inspection on Dolphin through an Artifact-ID Workspace API, covering deterministic Stage 0 data validation and Agent Stages 1-5.
---

# 华宝新能站内健康巡检

本 Skill 只处理华宝新能站内、Asia/Shanghai、CNY，以及流量、转化、商品三个维度和
37 项指标。不得扩展国家、站点、场景或数据源切换，也不得执行任何经营调整。

## 平台边界

- Dolphin 负责七个 Agent、任务书、业务计算、异常检测、packet、Schema、语义校验、
  Markdown 渲染和 Workflow。
- Workspace Server 负责日期身份、持久化、调度、封存、归档、删除和实际通知。
- 所有工作区读写必须使用合同 artifact ID，并绑定 run_id、incarnation_id 和
  platform_release_sha256；不得接受任意服务器路径。
- Agent 不持有宿主凭据、任意命令、存储控制或通知投递能力。

## 执行顺序与门禁

生产模式由 orchestrator_agent 每轮输出一个 action 与 stage。一次 dispatch 后必须先
observe，验收通过才可推进。固定 Stage 循环仅属于显式 fixture conformance harness。

1. data_operator_agent 只声明并核验 data_layer、calculate、detect、validate 四步。
   确定性代码生成业务数字，并校验目录顺序、冻结政策、评分、异常和证据。
2. inspector_agent 必须把全部确定性异常严格分区，每个异常恰属一个 case，并通过
   case_anomaly_partition_contract 自测。
3. diagnostician_agent 检验竞争假设，区分事实、反证、缺口与置信度，不把相关性写成
   因果。
4. advisor_agent 只输出 review_only 或 manual_adjustment；后者必须闭合异常、诊断、
   指标、人工调整、预期方向和验收标准。
5. auditor_agent 覆盖全部建议，并只解释 run_context 安全历史投影中当日精确到期的
   +1/+6 异常回看，不能把回看期变化直接宣称为因果。
6. reporter_agent 只汇总审核支持的建议。模型提交空 effect_reviews 槽，Runner 从已
   晋升 Auditor 结果按来源、数量和 SHA-256 确定性注入；固定 delivery_request 只声明
   投递意图，实际投递由服务器完成。

Stage 1～5 envelope 顶层严格包含 business 与 intelligence。自测状态必须 passed，所有
检查必须通过，unresolved_issues 必须为空。成功 Stage 不可覆盖；每 Stage 最多三个
attempt。恢复必须复用同一 incarnation，读取并核验已有 artifact SHA 后补齐缺失项。
恢复读取必须同时提供创建响应中持久化的 incarnation_id 与 platform_release_sha256；
不得只用可预测 run_id 查询工作区绑定。

## 运行输入

生产 backend 只接受 Dolphin 托管 Orchestrator 动作、Data Operator 声明及五个业务
Agent 的结构化响应，本仓不调用模型端点。fixture backend 必须显式选择，只用于本地
E2E，不能作为生产结果。

详细角色与恢复合同见 orchestration/agent-orchestration.md；机器合同见
orchestration/orchestration.contract.json；业务边界见 policies/。
