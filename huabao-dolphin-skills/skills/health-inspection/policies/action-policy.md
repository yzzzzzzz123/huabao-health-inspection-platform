# 建议策略

Advisor 只能输出 review_only 或 manual_adjustment。

- review_only：继续核查、分析或验证，不要求人工改变业务状态。
- manual_adjustment：要求业务人员修改投放、商品、页面、配置或其他经营状态。

manual_adjustment 必须同时给出关联 anomaly_id、diagnosis_id、目标 metric_id、具体调整、
预期变化方向和可验证的验收标准。任一环节证据不足时应改为 review_only，并明确待补证项，
不能用模糊措辞规避边界。

所有建议都必须说明负责人、优先级、收益、风险、依赖和可逆性。负责人无法精确映射时，
使用业务 Owner，不编造姓名。系统只记录建议和业务备注，不审批、不执行，也不采集实际
调整日期或生成过期状态。

异常回看由来源异常日期确定：次日为 +1，第 7 日为 +6。是否到期与建议类型、人工备注
或实际调整无关。observation_metrics 只能引用已存在的目标指标 ID；辅助观察对象写入说明
或验收标准。
