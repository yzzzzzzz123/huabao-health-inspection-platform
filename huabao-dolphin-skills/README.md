# Huabao Dolphin Skills

这是华宝健康巡检拆分后的纯 Dolphin 业务根，包含 7 个 Agent、Stage 0～5 业务合同、
37 项指标数据层、中央 Schema、确定性校验、渲染和 Workspace API 客户端。

## 边界

- Dolphin 负责任务书、Agent 推理、业务计算、异常检测、Schema/语义校验和 Workflow。
- Workspace Server 负责日期身份、持久化、调度、封存、归档、删除和实际外部投递。
- 所有工作区内容只按 artifact ID 读写，并绑定 run_id、incarnation_id 与
  platform_release_sha256；Dolphin 不接受任意服务器路径或宿主凭据。
- platform_release 正式对象严格只有七字段，bound_at 由服务器创建工作区时生成。
- run_context 是服务器冻结的安全历史投影；Dolphin 只读取其中最多近 7 日的 +1/+6
  到期来源，不扫描任何历史存储。

## CLI

    python -I skills/health-inspection/scripts/orchestrator_cli.py config
    python -I skills/health-inspection/scripts/orchestrator_cli.py release
    python -I skills/health-inspection/scripts/orchestrator_cli.py run \
      --business-date 2026-08-25 \
      --workspace-url http://127.0.0.1:8765 \
      --backend fixture

fixture 是明确标记的固定顺序本地合同演练，只用于 E2E 与恢复检查，不代表生产七 Agent
调度。生产使用 backend=dolphin，并通过 --hosted-responses 或
DOLPHIN_HOSTED_RESPONSES_JSON 注入 Dolphin 托管结果。

生产输入必须含：

- orchestrator：按轮次排列的结构化动作，每轮至少含 action 与 stage；每次 dispatch 后
  必须 observe，六个 Stage 全部 observe 后才能 finalize。
- data_operator：符合 data-operation.schema.json 的托管响应，明确声明固定四步
  command_plan；业务数字仍由确定性代码生成。
- inspector、diagnostician、advisor、auditor、reporter：各自严格的
  business/intelligence envelope。Reporter 原始 effect_reviews 必须为空数组，由 Runner
  从已晋升 Auditor 结果按数量和 SHA-256 确定性注入。

run 支持 --stop-after 与 --resume。恢复必须同时提供创建响应中持久化的
--incarnation-id 与 --platform-release-sha256；客户端不会用可预测 run_id 无头读取
workspace。恢复复用同一 incarnation，校验已有 artifact SHA，只补齐同一确定性
attempt 的缺失项；成功 Stage 不可覆盖。

成功 seal 的 CLI 顶层 `status`、`sealed` 与内层 seal receipt 必须同时表示完成态。
delivery manifest 绑定封存前稳定集合；Server 校验后生成包含 sealed `run_state` 的
workspace index 与 archive manifest，避免自引用并保留唯一受控状态跃迁。

## 迁移基线

机械迁移来源标识为 HEAD 63ef013a003aad3057cc732105d45da16a4cd301，初始冻结工作树
内容 SHA-256 为 c224aa3a00e9a362f3597d68c1dc5365c207945cb323522c7fcf284d2c11a059。
该基线描述当时冻结的工作树字节，不声称来源工作树等于 clean HEAD。

## 平台集成状态

dolphin/agents 与 dolphin/workflows 使用项目声明式 YAML 草案。当前环境没有 Dolphin
官方 YAML Schema 或平台校验器，因此字段级兼容性尚未验证，是部署前的明确集成门禁。
Python 业务合同、JSON Schema 和 Workspace API v2 绑定不依赖该 YAML 方言。
