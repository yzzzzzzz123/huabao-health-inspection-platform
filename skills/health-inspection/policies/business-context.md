# 业务范围

本 Skill 只支持华宝新能站内健康巡检，时区固定 Asia/Shanghai，币种固定 CNY，健康
维度固定为流量、转化、商品。不得扩展国家、站点、业务场景、可切换数据源或自动经营
执行。

技术目录固定 37 项：流量 12、转化 10、商品 15。metric_catalog.json 是运行时权威
目录，metric_runtime_policy.json 绑定其规范清单哈希。历史来源工作簿 SHA 只保留为
来源元数据；托管执行不读取或要求外部工作簿存在。

当前 Connector 使用按业务日期稳定生成的冻结 fixture，未来真实 API 适配必须保持同一
数据合同。精确数字只来自本次 facts 与 evidence catalog。证据不足时输出无法判断并列出
缺口，不得由 Agent 心算、补造阈值或改写评分。

每次运行使用 Workspace Server 返回的不可变 release 与 policy 绑定。Dolphin 不负责
日期唯一性、调度、存储、封存、归档或通知；这些能力只通过有界 Workspace API 投影与
业务流程衔接。
