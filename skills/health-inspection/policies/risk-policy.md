# 证据、审计与风险边界

每个异常必须引用本次 evidence catalog 中存在的证据和指标。诊断必须区分已验证事实、
相关性、竞争假设与数据缺口，不得把时序变化直接写成因果。

Auditor 必须逐项审核本期全部建议。审计结论只能是 supported、
supported_with_caveats 或 unsupported；unsupported 由 Reporter 列为待补证或暂不采纳，
不构成业务审批或自动执行门禁。

到期异常回看只来自 Workspace Server 在 run_context 中冻结的最多近 7 个日期安全投影。
Dolphin 不扫描历史存储。确定性代码仅在来源日 +1 和 +6 生成回看事实，Auditor 解释
improved、partially_improved、unchanged、worsened 或 insufficient_data。回看只描述
期间变化，不宣称由建议或人工调整导致。

Agent 与 Dolphin 业务代码不接收宿主密钥、任意网络端点或服务器文件路径。Reporter
只输出固定 delivery_request；实际外部投递、收据、归档、删除和完成态保护均由服务器
负责。任何建议仍由业务人员在线下判断和执行。
