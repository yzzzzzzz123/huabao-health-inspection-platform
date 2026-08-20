# {{AGENT_NAME}} 任务书

- run_id: {{RUN_ID}}
- business_date: {{BUSINESS_DATE}}
- stage: {{STAGE}}

## 目标

{{OBJECTIVE}}

## 强制边界

{{CONSTRAINTS}}

只使用注入的 taskbook、packet、中央输出 Schema 和职责所需的有界证据/政策投影。
只输出一个 JSON envelope，顶层严格包含 business 与 intelligence。不得访问任意
Workspace 路径、其他 Stage 原始响应、凭据或通知能力。
