# dsh-exec-privilege

给 DSH Desktop 加一个「执行权限」选择器：模型发起的文件修改、终端等工具可以明确地以
**普通用户 / 管理员 / SYSTEM / TrustedInstaller** 身份执行，默认普通用户。按钮位于
输入框工具行中「完全权限」权限选择器的右侧，样式与文档工坊的「文档修改」按钮一致。

## 行为

- **默认普通用户**：以当前用户的中等完整性令牌执行；即使 DSH 本体是管理员，工具也不会
  继承管理员权限。管理员组在令牌中为 deny-only。
- **管理员 / SYSTEM / TrustedInstaller**：切换前必须由用户在专用的「执行权限」确认框中批准；
  模型只能通过专用工具 `request_exec_privilege` 发起请求，**不能自行批准或提权**。如果 DSH
  本体权限不足，通过 UAC（管理员）或 UAC + 计划任务（SYSTEM）/ SYSTEM 复制 TI 令牌
  （TrustedInstaller）启动独立执行器。执行器只监听本机回环地址，并用一次性随机令牌认证。
- 菜单列出所有级别；**不可达的级别灰显并给出原因**（例如非管理员账户、UAC 被禁用、
  TrustedInstaller 服务被禁用、Windows 无 root）。
- 选择会持久化到 `~/.dsh/exec-privilege.json`；重启后若能直接继承 Host 现有令牌则恢复，
  需要额外提权的选择会回到普通用户并提示重新确认，不会静默提权。
- 切换是进程级的：新启动的工具使用新级别，已经在运行的命令继续以旧级别跑完。
- 不再需要高权限时切回「普通用户」即可；执行器退出。

## 实现概要

| 组件 | 作用 |
|---|---|
| `index.js` | 进程级 `execPrivilege` 服务、级别目录、UAC/计划任务/TI 启动、`/exec-privilege/*` 路由 |
| `worker.cjs` | 以目标令牌运行的执行器：接受 shell 与 fs 请求，回连 Host 的随机端口 |
| `fs.js` | 继承 `SandboxedFileSystem`，保留 read-only / workspace-write / full-access 路径策略，把读写转发给执行器 |
| `shell.js` | 继承 `SandboxPwshExecutor`，保留沙箱 confine/denial 判定，把最终 argv 交给执行器运行 |
| `native.cjs` | Koffi Win32 绑定：SAFER 普通用户令牌、完整性级别、计划任务、TI 服务令牌复制 |
| `client.js` | composer 按钮、菜单、不可达原因、专用确认框 |
| 专用工具 | `request_exec_privilege`：模型只发起请求，用户在专用确认框中决定 |

### 提权确认流程

1. 模型调用 `request_exec_privilege({ level, reason })`，工具只创建待确认请求并等待。
2. 客户端每 3 秒轮询状态，看到 `pendingRequest` 后在页面中央显示专用确认框；用户也可在
   「执行权限」菜单里选择目标级别，效果相同。
3. 用户点「允许」或「拒绝」。`/exec-privilege/decision` 需要浏览器会话 Cookie；模型所在
   的 shell 没有该 Cookie，因此不能自己批准。
4. 只有批准后 Host 才调用 `setLevel(..., { approvedRequestId })` 启动/切换执行器；拒绝或
   5 分钟超时都不会提权。

### 安全边界

- `/exec-privilege/state`、`/request`、`/decision`、`/level`、`/selftest` 都经过 DSH
  `connection.requestRejection()` 校验，只接受已认证的浏览器会话。
- 模型只能通过 `request_exec_privilege` 创建请求；`setLevel` 对高于当前级别的目标强制要求
  一个已由用户批准过的请求 id。
- 这是本地用户级边界：能读取浏览器 Cookie 数据库的同账户进程仍可绕过。需要更强边界时，
  应把确认放到独立的低权限 UI 进程或使用 OS 级同意机制。

Host 本体不重启、不提权；只有工具执行走目标令牌。这样会话、附件、日志等仍由 DSH 本体
正常处理。

## 安装

把本目录加入 desktop profile（`link:` 依赖 + bundle）后，Host 会把
`fs-sandbox` / `pwsh-sandbox` 替换为 `fs-privileged` / `shell-privileged`。
客户端 bundle 由 profile 的 `dsh.client` 声明自动加载。

## 诊断

```powershell
# 状态：本体身份、当前选择、各级别可达性与原因（需要浏览器会话 Cookie）
Invoke-RestMethod "http://127.0.0.1:<port>/exec-privilege/state"

# 发起提升请求；随后在页面确认框中批准（模型不能批准）
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:<port>/exec-privilege/request" `
  -ContentType 'application/json' -Body '{"level":"admin","reason":"manual test"}'

# 端到端自检：真实调用 ctx.fs / ctx.shell，返回写入、读取、目录列表和 whoami
Invoke-RestMethod "http://127.0.0.1:<port>/exec-privilege/selftest"
```

`selftest` 不再接受 `level` / `consent` 参数；切换级别必须走专用确认。可附加
`sandbox=workspace-write&workspace=<绝对路径>` 验证沙箱组合。

## 已知限制

- **SYSTEM / TrustedInstaller 与工作区内修改沙箱不兼容**：Windows ACL 沙箱的
  restricted-token runner 从会话 0 的系统令牌创建进程会返回 Win32 740。选择系统级身份时
  请把当前会话的权限预设切到「完全权限」；`read-only` / `workspace-write` 下终端命令会被
  沙箱拒绝（文件读写工具仍受路径策略约束）。
- **插件自有子进程不经过本选择器**：只有走 `ctx.shell` 与 `ctx.fs` 的能力会被路由；直接
  调用 `ctx.subprocess` 的插件（例如文档工坊 CLI）仍以 DSH 本体权限运行。终端侧栏同样
  使用独立的终端 seam，不在本选择器范围内。
- **UAC 取消**会快速返回错误；如果 UAC 已通过但提升后的启动器失败，最多等待 60–90 秒
  超时并给出错误。
- **POSIX**：界面会显示 root 但默认不可达；当前实现只在 Windows 上完整验证。

## 安全说明

- 执行器通过一次性 256-bit 随机令牌认证，只绑定 `127.0.0.1`。
- 普通用户执行器的配置对当前用户可读（它没有比当前用户更高的权限）；管理员 / SYSTEM /
  TI 执行器的配置用 `icacls` 限制为 Administrators + SYSTEM 可读。
- 选择 SYSTEM / TrustedInstaller 是高风险管理操作：确认框要求勾选风险提示。
- 权限由 DSH 本体所在账户的 UAC 策略约束；本功能不会绕过 UAC、组策略或服务 ACL。
