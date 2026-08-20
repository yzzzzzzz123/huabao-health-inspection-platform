# 华宝新能每日健康巡检任务书

- run_id: {{RUN_ID}}
- business_date: {{BUSINESS_DATE}}
- incarnation_id: {{INCARNATION_ID}}
- platform_release_sha256: {{PLATFORM_RELEASE_SHA256}}
- policy_sha256: {{POLICY_SHA256}}

固定范围：华宝新能站内、Asia/Shanghai、CNY，且只包含流量、转化、商品三个维度。

总控必须依据上一条受控结果选择下一动作并验收 Stage。所有工作区内容仅通过
Workspace API 的 artifact ID 读写。不得访问服务器路径、Git、SQLite、通知凭据或
网络投递能力。

成功 Stage 不可覆盖；失败 Stage 最多三个业务 attempt。恢复复用同一 incarnation，
核对已有 artifact SHA，并只补齐缺失文件。
