# worker 机制 spec（2026-10-28 grill 定稿）

> **设计真源**：2026-10-28 会话 grill，两轮 14 决策用户逐项确认（第一轮 Q1–Q10
> 「按推进的来做」，第二轮 Q11–Q14「按推荐来做」）。本文件是实施 issue 的引用
> 真源，另一个会话不读原对话也能据此实施。状态：**设计定稿；T1 契约面（#10）已
> 实施入库，运行时（#11 / #12）待实施**。
> 相关：ADR 0059（平台仓 ADR，管道语义三裁决）。

## 1. 背景与目标

插件（主插件 Store）需要并行纯计算能力：经宿主中介调用**内嵌 worker**——
即用即弃的 wasm 计算子资源，一线程一实例，用完即弃（释放线性内存），以获得
CPU 级并行。这是 ADR 0032/0034 预留的 worker 方向的落地，但形态是**常驻主插件
内嵌 worker 子资源**，不是 ADR 0032 的「整插件 ephemeral」（后者保持预留原义，
本期不动）。

## 2. 侦查事实（设计依赖的代码事实）

- 每插件一个 Store、全局共享一个 Engine（`WasmRuntime`）；不同 Store 实例可跨
  线程同时执行（p3 探针实证），**同实例调用串行**（mutex 实例锁 / event-loop
  属主门，票 08 已钉死为边界锁）——并行只能来自多 Store。
- wasmtime 跨 Store 不能直连，必须宿主中介（`call_guest` / intercall 是现成范式）。
- P3 async 化救不了并行（票 08 已退役：只能让出线程，不解除同实例串行）。
- **task 域（v20）是桌面独有**（`permission.rs` 登记 + `manager/task.rs` 在
  `desktop-assembly` 下）⇒ worker 调度不能复用 task 引擎，须双端新立。
- task 回调管道满载时终态事件也会丢（`task.rs` 派发路径），其权威兜底是 status
  快照；worker 事件直载输出、无快照可回退 ⇒ 丢弃 = 结果永久丢失。
- 内核已显性拒绝 epoch 中断（`engine.rs` 构建期校验：看门狗只用 fuel）⇒ 纯计算
  死循环被燃料兜住；阻塞 IO 型 worker（preopen）无墙钟抢占。
- 运行时壳已双支持 wasip2/p3 装配（p3 约束在 nightly 工具链，不在运行时）；
  AOT 缓存按文件键控（`aot_cache_key`），worker wasm 直接复用。
- `wasiPreopenDirs` 目前桌面 manifest 专属（移动 manifest 无 WASI 面）。
- 现状 = `lifecycle: "ephemeral"` 类型与校验闸门已落码但机制未实现（声明即
  加载期显性拒绝，`validate_lifecycle`）；`wasiPreopenDirs` 闸门同（ADR 0034）。

## 3. 设计决策（14 项定稿）

### 3.1 触发与执行模型

- **宿主中介**：主插件经 core.wit 的 `host-worker` import 调宿主，宿主启动
  worker（新 Store、新线程）。
- **一线程一 worker**：线程独占「instantiate → run → drop Store」生命周期，
  结束即释放线性内存。
- **每次运行 = 全新 Store，零共享状态**；同一 worker 并发多 job = 同一编译产物
  多实例；worker 间通信只能走主插件编排。
- **调度器在 `manager/` 双端机制层**（新模块），不复用桌面独有的 task 引擎；
  task 引擎「不接触 WASM/Store」边界声明一字不改。回调经 `GuestEventDispatcher`
  （双端已注入端口）投递。

### 3.2 调用面（WIT）

- **1 submit = 1 run**：`submit(worker, input) -> job_id`；fan-out = 连发 N 个
  submit（异步受理）。不做 plan/units。
- **传参**：JSON string（WIT `string`），输入上限 **1 MiB**（常量）；超大输入
  显性报错，文件路径留给 preopen 阶段。
- **回调**：`events-worker` 可选导出（探测范式同 events-binary），**只发终态**
  ——每 job 一条事件，直载输出：

  ```json
  { "jobId": "...", "state": "succeeded|failed|canceled",
    "output": "<json>", "error": "<仅 failed>" }
  ```

  无 queued/running 过程事件；无结果暂存仓库。
- **`cancel(job_id)`**：同批加入（host-worker 本就 bump，边际成本近零），语义
  = 标记取消。

### 3.3 管道语义

- **submit 受理语义**：进有界等待队列（深 **64**），溢出同步 Err。同步校验三
  件事 → 同步 Err：worker 名不存在 / 输入超限 / 队列满。运行期失败（实例化
  失败 / trap / 燃料耗尽）→ 终态 `failed` 事件。
- **回调队列满载 = 背压阻塞**：队列满则 worker 完成线程等待，消费即放行；阻塞
  上界 = 全局并发 8 条线程，guest 调用受燃料约束必终结 ⇒ 无死锁；Store 交付前
  不 drop（用完即关的延迟换正确性）。**不走 task 式丢弃**（无 status 快照可回
  退，丢弃 = 结果永久丢失）。
- **取消 / 停用 / 热重载**：标记取消 + 燃料自然终结 + 结果丢弃（投递通道已
  拆）；不承诺强杀（与 task 审计票 09 裁决 B 同立场）。preopen 落地时重开墙钟
  超时议题（epoch deadline 或 WASI 层超时）。

### 3.4 资源

- per-plugin 并发 **4** / 全局并发 **8**（与 task 池同量级）/ 单 worker 内存
  **继承默认 128 MiB**（`ResourceOverrides` 六字段可逐 worker 覆盖）/ 输入输出
  上限 **1 MiB**（常量落 `wasmnest-server-base` constants）。
- worker 燃料**独立预算**：与主插件同基数（`fuel_budget_for` 同源），per-worker
  `resourceOverrides.fuel_per_call` 覆盖。

### 3.5 契约面与权限

- **新建 `wit/worker.wit`**：自持 `world worker-guest`（零 import，仅 WASI 内建；
  world 名带 `-guest` 后缀 = 实施修正：WIT 同 package 内 interface 与 world 共享
  名字空间，导出接口必须保有契约名 `worker`，world 侧不能同名），
  export `wasmnest:plugin/worker@0.0.x` 接口的 `run: func(input: string) -> string`
  （JSON in/out）。worker 与主插件不同 world（主插件要 10 import + 3 必选导出），
  不能塞 core.wit。
- **`core.wit` 追加**（函数级追加 → 契约 patch bump）：import `host-worker`
  （`submit` + `cancel`）+ 可选导出 `events-worker`。双端全等交集（由「移动端
  一样」推出）。worker 组件版本不匹配 = 实例化失败（版本进 import 名，fail-visible）。
- **权限**：新增 `worker:run`（submit / cancel 同门）。真源
  `permission.rs`（PERMISSION_VOCABULARY / PERMISSION_API_MAP）→ SDK
  `gen:permissions` 重出 → 测试仓 `permission_vocabulary_lock`。
- §2.2 bump 全流程：`PACKAGE_VERSION` 0.0.1 → 0.0.2 + 全仓 `@0.0.1` 字面量同步
  （discovery-engine `routing.rs`/`lib.rs`、各域 `plugin_binding.rs`
  `MODULE_INTERFACES`）+ 平台 `compose-wit.mjs --all` + `check:wit` + 全部插件
  产物重建 + `check:manifest --print-hash`。**号段裁决（2026-10-28）**：AGENTS
  §2.2 的通用规则写「interface 增删 → minor」，本票新增的 `host-worker` /
  `events-worker` / `worker` 均为纯增量面（既有签名零变、worker world 独立且一期
  不进 compose），用户裁决**按本 spec 的 patch（0.0.2）执行**并在此留档。
  整数 ABI 版本已随 wit 包版本化退役
  （ADR 0051 D2），无需 ABI 数字 bump。

### 3.6 目标与装配

- **一期 wasip2 only**；p3 有真实需求再放行（只改文档，装配本就双支持）。
- worker 组件**零宿主 WIT import**（纯计算；「预留 WIT」= 装配点允许将来 link
  宿主域，首个候选 preopen）；WASI 内建（random/clock 等）与主插件同装配
  （`CoreConfig::wasi`）。
- **preopen 一期维持加载期拒绝**（`validate_preopen_category` 现状不动）；
  `lifecycle: ephemeral` 闸门同样不动。
- AOT 缓存按文件复用现有路径，无新机制。

### 3.7 打包与 manifest

- 插件包内 `worker/` 目录放 worker wasm；manifest 新增
  `workers: [{ name, file, wasmHash?, resourceOverrides? }]`（最小集）；主插件
  仍 `persistent`；`lifecycle: "ephemeral"` 整插件语义保留 ADR 0032 预留原义。
- worker 私属于声明插件，不可跨插件 submit；`wasmHash` 语义与主 wasm 一致
  （缺省不校验）；加载期校验：name 唯一、file 存在于 `worker/`。
- 不设 per-worker 并发数（per-plugin 配额已覆盖）。

## 4. 派生默认（grill 中声明不重问）

- submit 同步校验三件事（见 §3.3）；运行期失败 → 终态 `failed` 事件。
- worker 组件版本不匹配 = 实例化失败（fail-visible）。
- WASI 内建与主插件同装配；preopen / `lifecycle: ephemeral` 闸门维持现状。
- AOT 缓存与 fuel 注入复用既有路径。

## 5. 词汇表

| 术语 | 定义 |
| --- | --- |
| **worker** | 插件内嵌的即用即弃纯计算 wasm 组件（wasip2、零宿主 import），私属于声明插件 |
| **worker job** | 一次 worker 运行（job_id 标识，终态三值 succeeded/failed/canceled）；刻意避开既有「task」 |
| **task** | host-task 引擎既有词（桌面独有，v20），不动 |
| **ephemeral** | ADR 0032 整插件生命周期预留义，本期不在范围 |
| **背压** | 回调队列满时 worker 完成线程阻塞等待，不丢弃 |

## 6. 跨仓影响面

- **本仓（wasmnest-lib）**：`wit/worker.wit` 新增 + `core.wit` 追加 +
  `manifest.rs` workers 块 + validation 校验（新块；两闸门不动）+
  `manager/` worker 调度器（双端层新模块）+ `permission.rs` `worker:run` +
  `server-base` constants + `wasmnest-contract` worker 接口名常量。
  **不新建 crate、不动 `SPLIT_CRATES`。**
- **平台仓**：compose-wit 组 worker world 分片（T4）、双端 SDK guest 类型、
  双端宿主 `GuestEventDispatcher` worker 词汇接线、构建工具 `worker/` 产物支持。
- **应用仓**：示例插件（main + worker/ fan-out）。
- **测试仓**：`permission_vocabulary_lock` regen 断言；若 worker 词汇进跨端锁
  则补断言。

## 7. 票据映射（2026-10-28 已发布）

| 票 | 仓 | issue | blocked by |
| --- | --- | --- | --- |
| T1 契约面扩列 | wasmnest-lib | [#10](https://github.com/7ZAI/wasmnest-lib/issues/10)（kind:contract + cross-repo） | — |
| T2 运行时最小端到端 | wasmnest-lib | [#11](https://github.com/7ZAI/wasmnest-lib/issues/11) | T1 |
| T3 调度语义补齐 | wasmnest-lib | [#12](https://github.com/7ZAI/wasmnest-lib/issues/12) | T2 |
| T4 平台 SDK worker 构建链 | wasmnest（协调票内子任务） | [#39](https://github.com/7ZAI/wasmnest/issues/39) | T1（#10） |
| T5 桌面端到端 demo | wasmnest + wasmnest-apps（协调票内子任务） | [#39](https://github.com/7ZAI/wasmnest/issues/39) | T3（#12）+ T4 |
| T6 移动端接线与验证 | wasmnest（协调票内子任务） | [#39](https://github.com/7ZAI/wasmnest/issues/39) | T3（#12）+ T4 |
| 协调 issue | wasmnest | [#39](https://github.com/7ZAI/wasmnest/issues/39)（kind:feature + cross-repo） | — |

ADR 0059 已落平台仓 ADR 目录（索引同提交，`c72d7fc`）。spec 本文件已随实施分支入库（`.scratch/2026-10-28-worker-mechanism/spec.md`）。

## 8. 参考

- ADR 0059（平台仓 ADR）：worker 管道语义三裁决（背压 / 事件直载 /
  不复用 task 引擎）。
- ADR 0032（旧仓冻结）：实例生命周期策略预留；ADR 0034：wasiPreopenDirs
  worker 类别预留。
- 票 08（p3 探针，已退役）：同实例串行边界锁。
- 事实源：`wasmnest-wasm-core/src/manager/{task.rs,runtime.rs,runtime/engine.rs,
  runtime/wasi.rs}`、`wasmnest-server-base/src/constants.rs`（task 池 8 线程 /
  回调队列 64 / 任务墙钟 1h）、`wasmnest-host-kit/src/limits.rs`
  （MAX_PLUGIN_MEMORY_BYTES = 128 MiB）。
