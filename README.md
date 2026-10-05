# 安全审查 · 离线复核台

TUF 风格的 Root 轮换 / Targets 授权离线复核工具。安全审查员在页面录入**审查时刻**、**按版本排序的至多 6 份 Root 元数据**与**1 份 Targets 元数据**后，即可启动离线复核；还可追加录入**目标名**与**1 份可选的受委托 Targets 元数据**，核验具体目标是否只能由获委托角色发布。全部验签与规则计算在**浏览器 Worker** 内完成，页面不发出任何业务网络请求。

## 复核规则

- **签名覆盖范围**：仅覆盖字段名按 Unicode 码点排序后的规范 JSON（无空白）UTF-8 字节，且只针对 `signed` 对象。
- **密钥标识**：规范公钥对象（`{keytype, keyval, scheme}` 规范序列化）的 **SHA-256**（hex）；**仅接受 Ed25519**。
- **Root 链**：版本必须连续（v, v+1, …），首份为锚点（链外信任的初始可信根）。候选根必须**同时**获得「前一 Root 的 root 角色」与「自身 root 角色」的**足额不同签名**授权，才成为下一轮可信根。
- **Targets 授权**：最终 Targets 须由**最终根**的 targets 角色足额签名，且审查时刻**不晚于**过期时间；过期即拒绝，即使签名有效。
- **目标级复核（录入目标名时）**：Root 链与顶层 Targets 通过后，判断该目标由谁发布——
  - 顶层 Targets 的 `delegations.roles` 按**声明顺序**匹配目标名（路径规则：`*` 匹配任意字符序列、`?` 匹配单个字符），首个命中角色生效；
  - 命中 **terminating** 委托后，子元数据的签名、格式或过期校验失败即**停止并拒绝**，顶层同名摘要不得当作允许证据；**未终止**委托失败才可继续检查顶层目标；
  - 子元数据只能由该委托声明的 Ed25519 键与阈值授权；目标缺失、重复委托角色或非法路径规则均保留既有根轮次证据并返回首个阻断原因；
  - 未录入目标名时维持原有仅顶层 Targets 的复核结论。
- **逐轮可观测**：页面逐轮展示可信根版本迁移、两侧达阈值签名者（keyid 前缀）、**首个阻断证据**与最终允许的目标摘要；目标级复核额外展示实际采用角色、命中的路径规则、达阈值的不同签名者与目标摘要（length + hashes）。

### 拒绝分支（保留此前可信根）

| 证据代码 | 含义 |
| --- | --- |
| `SELF_THRESHOLD_NOT_MET` | 仅旧根达阈值，候选根自身 root 角色签名不足 |
| `FIRST_ROUND_DOUBLE_THRESHOLD_FAILED` / `DOUBLE_THRESHOLD_FAILED` | 首轮/后续轮双阈值均失败 |
| `PREV_THRESHOLD_NOT_MET` / `INSUFFICIENT_SIGNATURES` | 签名不足 |
| `VERSION_JUMP` | 版本跳跃（不连续） |
| `DUPLICATE_SIGNER` | 重复签名者 |
| `UNKNOWN_KEY` | 签名引用未知/未授权键 |
| `DUPLICATE_OBJECT_NAME` | 原始文本任意层级存在重复对象名 |
| `BAD_SIGNATURE` | `signed` 内容被篡改，验签失败 |
| `TARGETS_THRESHOLD_NOT_MET` / `TARGETS_EXPIRED` | Targets 签名不足 / 已过期 |
| `UNSUPPORTED_KEYTYPE` | 非 Ed25519 密钥 |
| `TARGET_NOT_FOUND` | 目标缺失：未获任何有效角色授权 |
| `DUPLICATE_DELEGATION_ROLE` | 重复委托角色 |
| `INVALID_PATH_PATTERN` | 非法路径规则（空路径串或空 paths 数组） |
| `MISSING_DELEGATED_METADATA` | 命中委托但未提供受委托 Targets 元数据 |
| `DELEGATION_THRESHOLD_NOT_MET` / `DELEGATION_EXPIRED` | 委托子元数据签名不足 / 已过期 |

## 本地运行

```bash
node scripts/build.js     # 页面构建 → dist/（含示例 fixtures）
node tests/run-tests.js   # 代码规则测试（32 项）
node server/server.js     # 静态页面服务，默认 8080 端口
# 打开 http://127.0.0.1:8080/ ，健康接口 http://127.0.0.1:8080/health
```

页面内置四份示例（与规则测试共用同一场景构造器）：**合法轮换**、**旧根单签拒绝**、**过期 Targets**、**委托目标**。

## Compose 验收

```bash
WEB_PORT=8080 docker compose up --build --exit-code-from verify
echo $?                  # 0 = 验收通过，非 0 = 验收失败
docker compose down
```

- `web`：静态页面服务，宿主端口由 `WEB_PORT` 配置（默认 8080），`/health` 返回健康响应。
- `verify`：依次执行 ① 页面构建 → ② 代码规则测试（合法轮换 / 旧根单签拒绝 / 过期 Targets / 委托目标等 32 项）→ ③ 健康接口与静态资源 HTTP 冒烟；完成后退出，以退出码报告验收状态。

## 目录结构

```
src/            复核引擎（浏览器 Worker 与 Node 共用的纯 ES 模块）
  canonical-json.js   规范 JSON 序列化 + 严格解析（重复对象名检测）
  crypto-adapter.js   Ed25519 验签 / SHA-256（WebCrypto 优先，Node 回退）
  verifier.js         逐轮复核规则引擎
web/            静态页面（录入表单、Worker、逐轮结果渲染）
server/         零依赖静态服务器（含 /health）
scripts/        build.js（页面构建）、verify.js（Compose 验收入口）、generate-fixtures.js
tests/          规则测试与场景构造器（真实 Ed25519 密钥签名）
```
