# 指标与判定策略

## 目录合同

metric_catalog.json 的 metrics 数组是 37 项指标 ID、position、维度、频率、名称、来源和
公式的权威顺序。校验必须与该数组逐项严格等值，不能按 HI 编号重新排序；例如 HI-036
位于目录第 16 项，HI-037 位于末项。ID 集合必须恰为 37 个且不得重复。

runtime policy 必须绑定目录的规范清单 SHA-256。来源工作簿名称与 SHA-256 仅作为来源
追溯元数据，运行时不得查找或读取外部工作簿。

## 冻结政策

每次运行只读取 artifact ID 为 data_layer_health_policy 的冻结政策。37 条 rules 与目录
顺序必须完全一致。规则覆盖状态只能是 evaluated、partially_evaluated 或 monitor_only；
没有完整阈值的指标不得伪装为正常或异常。

lower_bound、upper_bound 与特殊分支由确定性代码解释。HI-030 的“销售额为 0 且广告费
大于 0”分支始终由确定性代码执行，阈值只能影响其常规健康分档，不能关闭该分支。

## 评分

含 scoring_config 的政策按冻结的维度内指标整数权重和三维整数权重计算，区间也按政策
冻结。为兼容历史政策，缺少 scoring_config 时使用三维等权、维度内指标等权，以及
60/80 的总分与维度分档。Agent 不得改写权重、阈值、区间或分值上限。

所有当前值、基线值、判定、覆盖数、健康分和异常数都来自本次 data_layer_facts。文档、
提示词和历史运行中的数字都不能替代当次事实。
