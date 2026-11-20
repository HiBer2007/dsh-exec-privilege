// @local/dsh-exec-privilege
//
// Host side of the execution-privilege selector. One process-global selection
// decides which Windows token the agent's file and terminal tools execute
// under. The DSH host itself never changes privilege; each level is served by
// an out-of-process worker (medium SAFER token, elevated admin, SYSTEM, or
// TrustedInstaller) reached over a token-authenticated loopback connection.
import fs from 'node:fs'
import os from 'node:os'
import net from 'node:net'
import { spawn, spawnSync } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import { dirname, join } from 'node:path'
import { createRequire } from 'node:module'
import { findRuntimeDir, loadPackage, pluginDir } from './runtime.js'

const native = createRequire(import.meta.url)('./native.cjs')

const LEVELS = [
  {
    id: 'user',
    rank: 0,
    labelZh: '普通用户',
    labelEn: 'Normal user',
    shortZh: '普通用户',
    shortEn: 'User',
    descZh: '当前用户的中等完整性令牌；管理员组为拒绝状态。',
    descEn: 'The current user with a Medium-integrity token and Administrators deny-only.',
  },
  {
    id: 'admin',
    rank: 1,
    labelZh: '管理员',
    labelEn: 'Administrator',
    shortZh: '管理员',
    shortEn: 'Admin',
    descZh: 'Windows 管理员（高完整性）。需要 UAC 授权时会弹出系统提示。',
    descEn: 'A Windows administrator token (High integrity). UAC may prompt.',
  },
  {
    id: 'system',
    rank: 2,
    labelZh: 'SYSTEM',
    labelEn: 'SYSTEM',
    shortZh: 'SYSTEM',
    shortEn: 'SYSTEM',
    descZh: 'Windows 系统账户；可通过计划任务启动，能访问系统级资源。',
    descEn: 'The Windows system account, started through a scheduled task.',
  },
  {
    id: 'trustedinstaller',
    rank: 3,
    labelZh: 'TrustedInstaller',
    labelEn: 'TrustedInstaller',
    shortZh: 'TI',
    shortEn: 'TI',
    descZh: 'Windows 模块安装程序身份（SYSTEM + TrustedInstaller 服务组），可修改系统保护目录。',
    descEn: 'The Windows Modules Installer identity (SYSTEM plus the TrustedInstaller service group).',
  },
  {
    id: 'root',
    rank: 4,
    labelZh: 'root',
    labelEn: 'root',
    shortZh: 'root',
    shortEn: 'root',
    descZh: 'Linux/macOS 超级用户；Windows 上不可用。',
    descEn: 'The Linux/macOS superuser; unavailable on Windows.',
  },
]

const LEVEL_BY_ID = new Map(LEVELS.map((level) => [level.id, level]))
const CONFIG_DIR = join(os.tmpdir(), 'dsh-exec-privilege')
const SHELL_READER_CAP = 4 * 1024 * 1024

function nowIso() {
  return new Date().toISOString()
}

function errorText(error) {
  return error instanceof Error ? error.message : String(error)
}

function shellQuote(text) {
  return `"${String(text).replaceAll('"', '""')}"`
}

function base64(buffer) {
  return Buffer.from(buffer).toString('base64')
}

/** One in-memory bounded byte window with absolute stream offsets. */
class StreamWindow {
  constructor(cap = SHELL_READER_CAP) {
    this.cap = cap
    this.chunks = []
    this.offset = 0
    this.total = 0
    this.spillPath = undefined
  }

  append(chunk) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    if (buffer.length === 0) return
    this.chunks.push(buffer)
    this.total += buffer.length
    while (this.total - this.offset > this.cap && this.chunks.length > 0) {
      const head = this.chunks[0]
      const excess = this.total - this.offset - this.cap
      if (head.length <= excess) {
        this.chunks.shift()
        this.offset += head.length
      } else {
        this.chunks[0] = head.subarray(excess)
        this.offset += excess
      }
    }
  }

  readFrom(fromByte) {
    const from = Math.max(0, Number(fromByte) || 0)
    const lossy = from < this.offset
    const start = Math.max(from, this.offset)
    let chunks = this.chunks
    if (start > this.offset) {
      const skip = start - this.offset
      let remaining = skip
      chunks = []
      for (const chunk of this.chunks) {
        if (remaining >= chunk.length) {
          remaining -= chunk.length
          continue
        }
        chunks.push(chunk.subarray(remaining))
        remaining = 0
      }
    }
    let text = ''
    try {
      text = new TextDecoder('utf-8', { fatal: false }).decode(Buffer.concat(chunks))
    } catch {}
    return {
      text,
      lossy,
      nextOffset: this.total,
      ...(lossy && this.spillPath !== undefined ? { spillPath: this.spillPath } : {}),
    }
  }
}

/** A shell process served by a worker, shaped for `PwshLocalExecutor.executeArgv`. */
class WorkerShellHandle {
  constructor(connection, id, request) {
    this.connection = connection
    this.id = id
    this.request = request
    const stdoutMax = Number(request.stdio?.stdout?.maxBytes) || 65536
    const stderrMax = Number(request.stdio?.stderr?.maxBytes) || 65536
    this.stdout = new StreamWindow(Math.max(stdoutMax, 1024))
    this.stderr = new StreamWindow(Math.max(stderrMax, 1024))
    this.status = 'running'
    this.exitCode = null
    this.signal = null
    this.spawnedDeferred = Promise.withResolvers()
    this.doneDeferred = Promise.withResolvers()
    this.spawned = this.spawnedDeferred.promise
    this.done = this.doneDeferred.promise
    this.spawned.catch(() => {})
    this.done.catch(() => {})
    this.observed = {
      stdout: this.stdout,
      stderr: this.stderr,
    }
    this.collected = {
      stdout: this.stdout,
      stderr: this.stderr,
    }
  }

  event(event, message) {
    if (event === 'stdout' || event === 'stderr') {
      const window = event === 'stdout' ? this.stdout : this.stderr
      try {
        window.append(Buffer.from(String(message.data ?? ''), 'base64'))
      } catch {}
      return
    }
    if (event === 'spill') {
      const window = message.stream === 'stderr' ? this.stderr : this.stdout
      window.spillPath = message.path
      return
    }
    if (event === 'exit') {
      this.status = 'completed'
      this.exitCode = message.exitCode ?? null
      this.signal = message.signal ?? null
      this.spawnedDeferred.resolve({ pid: undefined })
      this.doneDeferred.resolve({ exitCode: this.exitCode, signal: this.signal })
      return
    }
    if (event === 'error') {
      this.status = 'killed'
      const error = new Error(message.message ?? 'worker shell process failed')
      this.spawnedDeferred.reject(error)
      this.doneDeferred.reject(error)
    }
  }

  fail(error) {
    this.status = 'killed'
    this.spawnedDeferred.reject(error)
    this.doneDeferred.reject(error)
  }

  terminate() {
    if (this.status !== 'running') return false
    this.status = 'killed'
    try {
      this.connection.send({ type: 'request', id: ++this.connection.nextId, op: 'shell.kill', shellId: this.id })
    } catch {}
    return true
  }

  readOutput() {
    // The shell tool's background path reads the offset windows directly; this
    // method is only kept for interface completeness.
    const out = this.stdout.readFrom(0)
    const err = this.stderr.readFrom(0)
    return {
      delta: `${out.text}${err.text ? `\n[stderr]\n${err.text}` : ''}`,
      lossy: out.lossy || err.lossy,
    }
  }
}

/** One authenticated worker connection. */
class WorkerConnection {
  constructor(service, socket, hello) {
    this.service = service
    this.socket = socket
    this.level = hello.level
    this.pid = hello.pid
    this.identity = hello.identity ?? {}
    this.connectedAt = nowIso()
    this.nextId = 0
    this.pending = new Map()
    this.shells = new Map()
    this.watchers = new Map()
    this.streams = new Map()
    this.closed = false
    this.buffer = ''
    socket.setEncoding('utf8')
    socket.on('data', (chunk) => this.onData(chunk))
    socket.on('error', (error) => this.onClose(error))
    socket.on('close', () => this.onClose())
  }

  attachPending(buffer) {
    if (buffer) this.onData(buffer)
  }

  send(message) {
    if (this.closed) return false
    try {
      this.socket.write(`${JSON.stringify(message)}\n`)
      return true
    } catch {
      return false
    }
  }

  onData(chunk) {
    this.buffer += chunk
    if (this.buffer.length > 256 * 1024 * 1024) {
      this.socket.destroy()
      return
    }
    let index
    while ((index = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, index)
      this.buffer = this.buffer.slice(index + 1)
      if (line.length === 0) continue
      let message
      try {
        message = JSON.parse(line)
      } catch {
        continue
      }
      this.dispatch(message)
    }
  }

  dispatch(message) {
    if (message?.type === 'response') {
      const pending = this.pending.get(message.id)
      if (pending === undefined) return
      this.pending.delete(message.id)
      clearTimeout(pending.timer)
      if (message.ok) pending.resolve(message.value)
      else pending.reject(workerError(message.error))
      return
    }
    if (message?.type === 'event') {
      const shell = this.shells.get(message.id)
      if (shell !== undefined) shell.event(message.event, message)
      return
    }
    if (message?.type === 'stream') {
      const queue = this.streams.get(message.id)
      if (queue !== undefined) queue.push({ text: message.text })
      return
    }
    if (message?.type === 'stream-end') {
      const queue = this.streams.get(message.id)
      if (queue !== undefined) {
        this.streams.delete(message.id)
        if (message.error) queue.fail(workerError(message.error))
        else queue.end()
      }
      return
    }
    if (message?.type === 'watch') {
      const entry = this.watchers.get(message.id)
      if (entry === undefined) return
      if (message.event === 'changed') entry.changed()
      else entry.changed(new Error(message.message ?? 'filesystem watch failed'))
    }
  }

  requestWithId(op, payload = {}, timeoutMs = 60000) {
    if (this.closed) return { id: 0, promise: Promise.reject(new Error('执行权限执行器连接已断开')) }
    const id = ++this.nextId
    const promise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`执行权限执行器在 ${timeoutMs}ms 内没有响应（${op}）`))
      }, timeoutMs)
      this.pending.set(id, { resolve, reject, timer })
      if (!this.send({ type: 'request', id, op, ...payload })) {
        this.pending.delete(id)
        clearTimeout(timer)
        reject(new Error('执行权限执行器连接已断开'))
      }
    })
    return { id, promise }
  }

  request(op, payload = {}, timeoutMs = 60000) {
    return this.requestWithId(op, payload, timeoutMs).promise
  }

  spawnShell(request) {
    const id = ++this.nextId
    const handle = new WorkerShellHandle(this, id, request)
    this.shells.set(id, handle)
    const stdoutMaxBytes = Number(request.stdio?.stdout?.maxBytes) || 65536
    const stderrMaxBytes = Number(request.stdio?.stderr?.maxBytes) || 65536
    const spillMaxBytes = Number(request.stdio?.stdout?.spill?.maxBytes) || 0
    const stdin = request.stdio?.stdin?.data
    this.pending.set(id, {
      resolve: () => handle.spawnedDeferred.resolve({ pid: undefined }),
      reject: (error) => handle.fail(error),
      timer: setTimeout(() => {
        this.pending.delete(id)
        handle.fail(new Error('执行权限执行器未能启动命令'))
      }, 30000),
    })
    this.send({
      type: 'request',
      id,
      op: 'shell.spawn',
      argv: request.argv,
      cwd: request.cwd,
      env: request.env ?? {},
      ...(typeof stdin === 'string' ? { stdin } : {}),
      graceMs: request.graceMs,
      stdoutMaxBytes,
      stderrMaxBytes,
      spillMaxBytes,
    })
    return handle
  }

  shellEvent(id) {
    return this.shells.get(id)
  }

  async unwatch(watchId) {
    try {
      await this.request('fs.unwatch', { watchId }, 5000)
    } catch {}
    this.watchers.delete(watchId)
  }

  async streamText(target) {
    const id = ++this.nextId
    const queue = new AsyncQueue()
    this.streams.set(id, queue)
    if (!this.send({ type: 'request', id, op: 'fs.streamText', target })) {
      this.streams.delete(id)
      queue.fail(new Error('执行权限执行器连接已断开'))
    }
    return queue
  }

  async shutdown(reason = 'shutdown') {
    if (this.closed) return
    try {
      this.send({ type: 'request', id: ++this.nextId, op: 'shutdown' })
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 150))
    try {
      this.socket.end()
    } catch {}
    this.onClose(new Error(reason))
    // Best effort: workers exit on socket close; also terminate the known PID.
    if (this.pid) {
      try {
        spawnSync('C:\\Windows\\System32\\taskkill.exe', ['/PID', String(this.pid), '/T', '/F'], {
          windowsHide: true,
          stdio: 'ignore',
        })
      } catch {}
    }
  }

  onClose(error) {
    if (this.closed) return
    this.closed = true
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer)
      pending.reject(new Error(`执行权限执行器连接已断开${error ? `：${errorText(error)}` : ''}`))
    }
    this.pending.clear()
    for (const shell of this.shells.values()) shell.fail(new Error('执行权限执行器连接已断开'))
    this.shells.clear()
    for (const queue of this.streams.values()) queue.fail(new Error('执行权限执行器连接已断开'))
    this.streams.clear()
    for (const entry of this.watchers.values()) entry.changed(new Error('执行权限执行器连接已断开'))
    this.watchers.clear()
    this.service.onConnectionClosed(this)
  }
}

function workerError(payload) {
  const error = new Error(payload?.message ?? 'execution privilege worker error')
  if (payload?.name) error.name = payload.name
  if (payload?.code !== undefined) error.code = payload.code
  return error
}

/** Minimal async queue used for worker streamed text. */
class AsyncQueue {
  constructor() {
    this.items = []
    this.waiters = []
    this.ended = false
    this.error = undefined
  }

  push(item) {
    if (this.ended) return
    const waiter = this.waiters.shift()
    if (waiter) waiter.resolve({ value: item, done: false })
    else this.items.push(item)
  }

  end() {
    if (this.ended) return
    this.ended = true
    for (const waiter of this.waiters.splice(0)) waiter.resolve({ value: undefined, done: true })
  }

  fail(error) {
    if (this.ended) return
    this.ended = true
    this.error = error
    for (const waiter of this.waiters.splice(0)) waiter.reject(error)
  }

  next() {
    if (this.error) return Promise.reject(this.error)
    if (this.items.length > 0) return Promise.resolve({ value: this.items.shift(), done: false })
    if (this.ended) return Promise.resolve({ value: undefined, done: true })
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }))
  }

  async *[Symbol.asyncIterator]() {
    while (true) {
      const item = await this.next()
      if (item.done) return
      yield item.value
    }
  }
}

/** Host service and HTTP surface for the selector. */
export const inject = ['webServer', 'tools']

class ExecPrivilegeService {
  constructor(ctx) {
    this.ctx = ctx
    this.runtimeDir = findRuntimeDir()
    this.pluginDir = pluginDir
    this.server = undefined
    this.port = undefined
    this.token = undefined
    this.host = undefined
    this.hostLevel = undefined
    this.selected = 'user'
    this.connections = new Map()
    this.starting = new Map()
    this.waiters = new Map()
    this.launched = new Map()
    this.uacFailures = new Map()
    this.configFiles = new Set()
    this.bootstrapFiles = new Set()
    this.switching = false
    this.lastError = undefined
    this.disposed = false
    this.lastStart = undefined
    this.pendingRequest = undefined
    this.pendingDecision = undefined
    this.pendingTimer = undefined
    this.ready = this.init()
    this.ready.catch((error) => {
      this.lastError = errorText(error)
    })
    ctx.effect(() => () => {
      this.dispose()
    }, 'exec-privilege: dispose workers')
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/exec-privilege/state',
      handler: (request, response) => this.handleState(request, response),
    }), 'exec-privilege: state route')
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/exec-privilege/level',
      handler: (request, response) => this.handleLevel(request, response),
    }), 'exec-privilege: level route')
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/exec-privilege/request',
      handler: (request, response) => this.handleRequest(request, response),
    }), 'exec-privilege: request route')
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/exec-privilege/decision',
      handler: (request, response) => this.handleDecision(request, response),
    }), 'exec-privilege: decision route')
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/exec-privilege/selftest',
      handler: (request, response) => this.handleSelftest(request, response),
    }), 'exec-privilege: selftest route')
  }

  async init() {
    if (!this.runtimeDir) throw new Error('exec-privilege: cannot locate the DSH runtime directory')
    if (!native.isWindows()) {
      // The UI still renders; only `user` is meaningful outside Windows.
      this.host = { userName: process.env.USER ?? 'user', integrity: 'User', groups: [] }
      this.hostLevel = 'user'
      this.selected = 'user'
      return
    }
    this.host = native.inspectToken(this.runtimeDir)
    this.hostLevel = this.resolveHostLevel(this.host)
    this.uacEnabled = native.uacEnabled(this.runtimeDir)
    this.trustedInstallerService = this.probeTrustedInstallerService()
    fs.mkdirSync(CONFIG_DIR, { recursive: true })
    this.server = net.createServer((socket) => this.accept(socket))
    this.server.on('error', (error) => {
      this.lastError = `执行权限通道错误：${errorText(error)}`
    })
    await new Promise((resolve, reject) => {
      this.server.once('error', reject)
      this.server.listen(0, '127.0.0.1', () => {
        this.server.removeListener('error', reject)
        resolve()
      })
    })
    this.port = this.server.address().port
    this.token = randomBytes(32).toString('hex')
    // Restore only selections that need no elevation beyond the Host token.
    // A saved elevated level on a weaker Host stays pending until the user
    // confirms again, so a restart never silently re-elevates.
    const saved = this.readPersistedLevel()
    this.selected = 'user'
    const startUserWorker = () => {
      if (this.hostLevel === 'user') return
      void this.ensureWorker('user').catch((error) => {
        this.lastError = `默认普通用户执行器启动失败：${errorText(error)}`
      })
    }
    if (saved === this.hostLevel) {
      this.selected = saved
    } else if (saved === 'user') {
      startUserWorker()
    } else if (saved !== undefined && LEVEL_BY_ID.has(saved)) {
      this.pendingRestore = saved
      this.lastError = `上次选择的「${LEVEL_BY_ID.get(saved)?.labelZh ?? saved}」在重启后需要重新确认；当前已回到普通用户`
      startUserWorker()
    } else {
      startUserWorker()
    }
  }

  persistenceFile() {
    const home = process.env.DSH_HOME && process.env.DSH_HOME.length > 0 ? process.env.DSH_HOME : join(os.homedir(), '.dsh')
    return join(home, 'exec-privilege.json')
  }

  readPersistedLevel() {
    try {
      const value = JSON.parse(fs.readFileSync(this.persistenceFile(), 'utf8'))
      return typeof value?.selected === 'string' && LEVEL_BY_ID.has(value.selected) ? value.selected : undefined
    } catch {
      return undefined
    }
  }

  persistLevel(level) {
    try {
      const file = this.persistenceFile()
      fs.mkdirSync(dirname(file), { recursive: true })
      fs.writeFileSync(file, JSON.stringify({ selected: level, updatedAt: nowIso() }, null, 2))
    } catch {}
  }

  resolveHostLevel(info) {
    if (info?.isTrustedInstaller) return 'trustedinstaller'
    if (info?.isSystem) return 'system'
    if (info?.isAdmin) return 'admin'
    return 'user'
  }

  probeTrustedInstallerService() {
    if (!native.isWindows()) return { exists: false, disabled: false }
    const query = spawnSync('C:\\Windows\\System32\\sc.exe', ['query', 'TrustedInstaller'], { encoding: 'utf8', windowsHide: true })
    if (query.status !== 0) return { exists: false, disabled: false }
    const config = spawnSync('C:\\Windows\\System32\\sc.exe', ['qc', 'TrustedInstaller'], { encoding: 'utf8', windowsHide: true })
    const startType = /START_TYPE\s*:\s*(\d+)/.exec(config.stdout ?? '')?.[1]
    return { exists: true, disabled: startType === '4' }
  }

  dispose() {
    if (this.disposed) return
    this.disposed = true
    for (const connection of this.connections.values()) void connection.shutdown('service disposed')
    this.connections.clear()
    for (const launch of this.launched.values()) {
      try {
        launch.close()
      } catch {}
    }
    this.launched.clear()
    try {
      this.server?.close()
    } catch {}
    for (const file of this.configFiles) {
      try {
        fs.rmSync(file, { force: true })
      } catch {}
    }
    for (const file of this.bootstrapFiles) {
      try {
        fs.rmSync(file, { force: true })
      } catch {}
    }
    this.configFiles.clear()
    this.bootstrapFiles.clear()
  }

  needsWorker() {
    return this.selected !== this.hostLevel
  }

  selectedConnection() {
    return this.connections.get(this.selected)
  }

  onConnectionClosed(connection) {
    if (this.connections.get(connection.level) === connection) this.connections.delete(connection.level)
  }

  /** Accept one worker handshake and register the connection. */
  accept(socket) {
    let buffer = ''
    let settled = false
    const timer = setTimeout(() => {
      if (!settled) {
        try {
          socket.destroy()
        } catch {}
      }
    }, 10000)
    const onData = (chunk) => {
      if (settled) return
      buffer += chunk.toString('utf8')
      const index = buffer.indexOf('\n')
      if (index < 0) {
        if (buffer.length > 1024 * 1024) socket.destroy()
        return
      }
      const line = buffer.slice(0, index)
      const rest = buffer.slice(index + 1)
      settled = true
      clearTimeout(timer)
      socket.removeListener('data', onData)
      let hello
      try {
        hello = JSON.parse(line)
      } catch {
        socket.destroy()
        return
      }
      if (hello?.type !== 'hello' || hello.token !== this.token || !LEVEL_BY_ID.has(hello.level)) {
        socket.destroy()
        return
      }
      const previous = this.connections.get(hello.level)
      if (previous !== undefined && !previous.closed) {
        void previous.shutdown('superseded')
      }
      const connection = new WorkerConnection(this, socket, hello)
      this.connections.set(hello.level, connection)
      connection.attachPending(rest)
      const waiter = this.waiters.get(hello.level)
      if (waiter !== undefined) {
        this.waiters.delete(hello.level)
        clearTimeout(waiter.timer)
        waiter.resolve(connection)
      }
      this.lastError = undefined
    }
    socket.on('data', onData)
    socket.on('error', () => {})
  }

  waitForLevel(level, timeoutMs) {
    const existing = this.connections.get(level)
    if (existing !== undefined && !existing.closed) return Promise.resolve(existing)
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters.delete(level)
        reject(new Error(`启动「${LEVEL_BY_ID.get(level)?.labelZh ?? level}」执行器超时`))
      }, timeoutMs)
      this.waiters.set(level, { resolve, reject, timer })
    })
  }

  async ensureWorker(level) {
    if (this.disposed) throw new Error('执行权限服务已停止')
    await this.ready
    if (level === this.hostLevel) return undefined
    const existing = this.connections.get(level)
    if (existing !== undefined && !existing.closed) return existing
    if (this.starting.has(level)) return this.starting.get(level)
    const promise = this.startWorker(level).finally(() => this.starting.delete(level))
    this.starting.set(level, promise)
    return promise
  }

  async startWorker(level) {
    const startedAt = Date.now()
    this.lastStart = { level, startedAt }
    const taskName = level === 'system' ? this.taskName(level) : undefined
    const configPath = this.writeConfig(level, taskName ? { taskName } : {})
    const bootstrap = this.writeBootstrap(level, configPath)
    const uacFailure = Promise.withResolvers()
    uacFailure.promise.catch(() => {})
    this.uacFailures.set(level, uacFailure)
    let connection
    try {
      await this.launchWorker(level, bootstrap, configPath, taskName)
      connection = await Promise.race([
        this.waitForLevel(level, level === 'system' ? 60000 : 90000),
        uacFailure.promise.then(() => {
          throw new Error('UAC 授权被取消或提升请求失败')
        }),
      ])
      return connection
    } catch (error) {
      this.lastError = `启动「${LEVEL_BY_ID.get(level)?.labelZh ?? level}」执行器失败：${errorText(error)}`
      throw error
    } finally {
      this.uacFailures.delete(level)
      // The worker has already parsed its config by the time the handshake
      // completes; on failure nothing else will read these files.
      this.safeRemove(configPath)
      this.safeRemove(bootstrap)
    }
  }

  async launchWorker(level, bootstrap, configPath, taskName) {
    if (level === 'user') {
      if (this.hostLevel === 'user') return
      const sessionId = this.hostLevel === 'admin' ? undefined : this.activeConsoleSession()
      const normal = native.createNormalUserToken(this.runtimeDir, sessionId === undefined ? {} : { sessionId })
      try {
        const launched = native.launchWithToken(this.runtimeDir, normal.token, `"C:\\Windows\\System32\\cmd.exe" /c "${bootstrap}"`, {
          cwd: os.homedir(),
        })
        this.trackLaunch(level, launched)
      } finally {
        normal.close()
      }
      return
    }
    if (level === 'admin') {
      if (this.hostLevel === 'admin' || this.hostLevel === 'system' || this.hostLevel === 'trustedinstaller') {
        throw new Error('当前本体权限不低于管理员，不需要独立的管理员执行器')
      }
      this.launchElevated(bootstrap, level)
      return
    }
    if (level === 'system') {
      if (this.hostLevel === 'system') return
      if (this.hostLevel === 'admin' || this.hostLevel === 'trustedinstaller') {
        native.createSystemTask(this.runtimeDir, taskName, bootstrap)
        return
      }
      // Medium host: one UAC bootstrap creates and runs the SYSTEM task.
      const create = this.writeTaskBootstrap(level, bootstrap, taskName)
      this.launchElevated(create, level)
      return
    }
    if (level === 'trustedinstaller') {
      if (this.hostLevel === 'trustedinstaller') return
      const system = await this.ensureWorker('system')
      try {
        await system.request('spawn-worker', {
          level: 'trustedinstaller',
          configPath,
        }, 90000)
      } finally {
        // The SYSTEM worker launches the TI process synchronously; the TI
        // worker reads its config immediately after CreateProcessAsUser.
        await new Promise((resolve) => setTimeout(resolve, 250))
      }
      return
    }
    throw new Error(`不支持的执行权限：${level}`)
  }

  trackLaunch(level, launched) {
    const previous = this.launched.get(level)
    if (previous !== undefined) {
      try {
        previous.close()
      } catch {}
    }
    this.launched.set(level, launched)
  }

  launchElevated(bootstrap, level) {
    const child = native.launchElevatedBootstrap(this.runtimeDir, bootstrap)
    let stderr = ''
    child.stderr?.setEncoding('utf8')
    child.stderr?.on('data', (chunk) => {
      stderr = (stderr + chunk).slice(-8192)
    })
    child.on('error', () => {})
    child.on('exit', (code) => {
      if (code !== 0) {
        const detail = stderr.trim() || `PowerShell exited with ${String(code)}`
        this.lastError = `UAC 提权失败：${detail}`
        const failure = this.uacFailures.get(level)
        if (failure !== undefined) failure.resolve()
      }
    })
    return child
  }

  activeConsoleSession() {
    try {
      const api = native.bindings(this.runtimeDir)
      // WTSGetActiveConsoleSessionId is not part of the shared binding table;
      // fall back to the host's own session if koffi cannot resolve it.
      return this.host?.sessionId
    } catch {
      return this.host?.sessionId
    }
  }

  taskName(level) {
    return `DSH-ExecPrivilege-${level}-${randomUUID().slice(0, 8)}`
  }

  writeConfig(level, extra = {}) {
    const file = join(CONFIG_DIR, `worker-${level}-${randomUUID()}.json`)
    const payload = {
      port: this.port,
      token: this.token,
      level,
      runtimeDir: this.runtimeDir,
      exePath: process.execPath,
      workerScript: join(this.pluginDir, 'worker.cjs'),
      cwd: os.homedir(),
      spillDir: join(CONFIG_DIR, 'spill'),
      logPath: join(CONFIG_DIR, `worker-${level}.log`),
      hostPid: process.pid,
      diffBasisMaxBytes: 10 * 1024 * 1024,
      ...extra,
    }
    fs.writeFileSync(file, JSON.stringify(payload, null, 2), { mode: 0o600 })
    this.configFiles.add(file)
    native.configDacl(this.runtimeDir, file, level === 'user' ? 'user' : 'elevated')
    return file
  }

  writeBootstrap(level, configPath) {
    const file = join(CONFIG_DIR, `bootstrap-${level}-${randomUUID()}.cmd`)
    const lines = [
      '@echo off',
      'set "ELECTRON_RUN_AS_NODE=1"',
      `"${process.execPath}" "${join(this.pluginDir, 'worker.cjs')}" --config "${configPath}"`,
      '',
    ]
    fs.writeFileSync(file, lines.join('\r\n'), { encoding: 'ascii' })
    this.bootstrapFiles.add(file)
    return file
  }

  writeTaskBootstrap(level, workerBootstrap, taskName) {
    const file = join(CONFIG_DIR, `create-task-${level}-${randomUUID()}.cmd`)
    const schtasks = 'C:\\Windows\\System32\\schtasks.exe'
    const lines = [
      '@echo off',
      `"${schtasks}" /Create /TN "${taskName}" /TR "${workerBootstrap}" /SC ONCE /ST 23:59 /RU SYSTEM /RL HIGHEST /F`,
      `"${schtasks}" /Run /TN "${taskName}"`,
      '',
    ]
    fs.writeFileSync(file, lines.join('\r\n'), { encoding: 'ascii' })
    this.bootstrapFiles.add(file)
    return file
  }

  safeRemove(file) {
    this.configFiles.delete(file)
    this.bootstrapFiles.delete(file)
    try {
      fs.rmSync(file, { force: true })
    } catch {}
  }

  rankOf(level) {
    return LEVEL_BY_ID.get(level)?.rank ?? -1
  }

  capabilities() {
    const windows = native.isWindows()
    const host = this.host ?? {}
    const hostLevel = this.hostLevel ?? 'user'
    const adminMember = Boolean(host.isAdminMember ?? host.isAdmin)
    const uac = this.uacEnabled === true
    let adminReachable = false
    let adminReasonZh = ''
    let adminReasonEn = ''
    if (windows) {
      if (hostLevel === 'admin') adminReachable = true
      else if (hostLevel === 'user') {
        if (!adminMember) {
          adminReasonZh = '当前 Windows 账户不属于 Administrators 组'
          adminReasonEn = 'The current Windows account is not in Administrators'
        } else if (!uac) {
          adminReasonZh = 'UAC 已被禁用，无法通过授权提升到管理员'
          adminReasonEn = 'UAC is disabled, so no administrator token can be obtained'
        } else adminReachable = true
      } else {
        adminReasonZh = 'DSH 本体以系统级身份运行，无法切换到交互式管理员'
        adminReasonEn = 'DSH itself runs with a system-level token; an interactive administrator is unavailable'
      }
    } else {
      adminReasonZh = 'Windows 之外没有“管理员”这一执行权限'
      adminReasonEn = 'The administrator level is Windows-specific'
    }

    let userReachable = true
    let userReasonZh = ''
    let userReasonEn = ''
    if (!windows) {
      userReachable = true
    } else if (!['user', 'admin', 'system', 'trustedinstaller'].includes(hostLevel)) {
      userReachable = false
      userReasonZh = '无法识别 DSH 本体的 Windows 身份'
      userReasonEn = 'The DSH host token could not be classified'
    }

    let systemReachable = false
    let systemReasonZh = ''
    let systemReasonEn = ''
    if (!windows) {
      systemReasonZh = 'SYSTEM 是 Windows 账户'
      systemReasonEn = 'SYSTEM is a Windows account'
    } else if (hostLevel === 'system') systemReachable = true
    else if (hostLevel === 'trustedinstaller') systemReachable = true
    else if (!adminReachable) {
      systemReasonZh = '需要先具备管理员权限才能启动 SYSTEM 执行器'
      systemReasonEn = 'Administrator access is required to start a SYSTEM worker'
    } else {
      systemReachable = true
    }

    let tiReachable = false
    let tiReasonZh = ''
    let tiReasonEn = ''
    if (!windows) {
      tiReasonZh = 'TrustedInstaller 是 Windows 服务身份'
      tiReasonEn = 'TrustedInstaller is a Windows service identity'
    } else if (hostLevel === 'trustedinstaller') tiReachable = true
    else if (!systemReachable) {
      tiReasonZh = '需要先能启动 SYSTEM 执行器（TrustedInstaller 令牌只能由 SYSTEM 复制）'
      tiReasonEn = 'A SYSTEM worker is required first (only SYSTEM can duplicate the TrustedInstaller token)'
    } else if (this.trustedInstallerService?.exists === false) {
      tiReasonZh = '系统上没有 TrustedInstaller 服务'
      tiReasonEn = 'The TrustedInstaller service is not installed'
    } else if (this.trustedInstallerService?.disabled === true) {
      tiReasonZh = 'TrustedInstaller 服务已被禁用'
      tiReasonEn = 'The TrustedInstaller service is disabled'
    } else {
      tiReachable = true
    }

    let rootReachable = false
    let rootReasonZh = ''
    let rootReasonEn = ''
    if (windows) {
      rootReasonZh = 'Windows 没有 root 账户；root 仅适用于 Linux/macOS'
      rootReasonEn = 'Windows has no root account; root applies to Linux/macOS only'
    } else {
      rootReachable = typeof process.getuid === 'function' && process.getuid() === 0
      if (!rootReachable) {
        rootReasonZh = '当前进程不是 root，且尚未实现 POSIX sudo 提权'
        rootReasonEn = 'The current process is not root and POSIX sudo elevation is not implemented'
      }
    }

    return {
      user: { reachable: userReachable, reasonZh: userReasonZh, reasonEn: userReasonEn },
      admin: { reachable: adminReachable, reasonZh: adminReasonZh, reasonEn: adminReasonEn, needsElevation: windows && hostLevel !== 'admin' },
      system: { reachable: systemReachable, reasonZh: systemReasonZh, reasonEn: systemReasonEn, needsElevation: windows && hostLevel !== 'system' },
      trustedinstaller: { reachable: tiReachable, reasonZh: tiReasonZh, reasonEn: tiReasonEn, needsElevation: windows && hostLevel !== 'trustedinstaller' },
      root: { reachable: rootReachable, reasonZh: rootReasonZh, reasonEn: rootReasonEn },
    }
  }

  levelsView() {
    const capabilities = this.capabilities()
    const currentRank = this.rankOf(this.selected)
    return LEVELS.filter((level) => level.id !== 'root' || process.platform !== 'win32' ? true : true).map((level) => {
      const capability = capabilities[level.id] ?? { reachable: false, reasonZh: '未知权限', reasonEn: 'Unknown level' }
      const connection = this.connections.get(level.id)
      const direct = level.id === this.hostLevel
      return {
        ...level,
        reachable: capability.reachable,
        reasonZh: capability.reasonZh ?? '',
        reasonEn: capability.reasonEn ?? '',
        needsElevation: capability.needsElevation === true,
        needsConsent: level.rank > currentRank,
        selected: level.id === this.selected,
        active: level.id === this.selected && (direct || (connection !== undefined && !connection.closed)),
        direct,
        worker: connection !== undefined && !connection.closed
          ? { pid: connection.pid, identity: connection.identity, connectedAt: connection.connectedAt }
          : null,
      }
    })
  }

  effective() {
    if (this.selected === this.hostLevel) {
      return {
        level: this.selected,
        direct: true,
        ready: true,
        identity: this.host,
      }
    }
    const connection = this.connections.get(this.selected)
    if (connection === undefined || connection.closed) {
      return { level: this.selected, direct: false, ready: false, identity: null }
    }
    return {
      level: this.selected,
      direct: false,
      ready: true,
      pid: connection.pid,
      identity: connection.identity,
    }
  }

  state() {
    const snapshot = {
      ok: true,
      platform: process.platform,
      generatedAt: nowIso(),
      host: {
        level: this.hostLevel ?? 'user',
        identity: this.host ?? null,
      },
      selected: this.selected,
      pendingRestore: this.pendingRestore ?? null,
      pendingRequest: this.pendingRequest === undefined
        ? null
        : {
            id: this.pendingRequest.id,
            level: this.pendingRequest.level,
            reason: this.pendingRequest.reason,
            source: this.pendingRequest.source,
            createdAt: this.pendingRequest.createdAt,
          },
      effective: this.effective(),
      switching: this.switching,
      starting: [...this.starting.keys()],
      lastError: this.lastError ?? null,
      levels: this.levelsView(),
      port: this.port ?? null,
    }
    try {
      const marker = `${snapshot.host.level}|${snapshot.selected}|${snapshot.effective.ready}|${snapshot.effective.direct}|${snapshot.host.identity?.integrity ?? '?'}`
      if (this.lastStateMarker !== marker) {
        this.lastStateMarker = marker
        fs.appendFileSync(join(CONFIG_DIR, 'state.log'), `${nowIso()} ${marker}\n`)
      }
    } catch {}
    return snapshot
  }

  async setLevel(level, options = {}) {
    await this.ready
    const descriptor = LEVEL_BY_ID.get(level)
    if (descriptor === undefined) throw new Error(`未知执行权限：${level}`)
    const capabilities = this.capabilities()
    const capability = capabilities[level]
    if (!capability?.reachable) {
      throw new Error(capability?.reasonZh || `执行权限「${descriptor.labelZh}」当前不可达`)
    }
    // Any privilege increase must carry the id of a request the user approved
    // in the dedicated confirmation surface. A model tool call cannot forge it;
    // the sole path to a decision is the cookie-authenticated browser route.
    if (descriptor.rank > this.rankOf(this.selected) && typeof options.approvedRequestId !== 'string') {
      throw new Error('提升执行权限必须由用户在专用确认中批准')
    }
    if (this.switching) throw new Error('正在切换执行权限，请稍候')
    if (level === this.selected) {
      if (level === this.hostLevel) return this.state()
      await this.ensureWorker(level)
      return this.state()
    }
    this.switching = true
    this.lastError = undefined
    try {
      if (level !== this.hostLevel) await this.ensureWorker(level)
      this.selected = level
      this.pendingRestore = undefined
      this.persistLevel(level)
      for (const id of [...this.connections.keys()]) {
        if (id === level) continue
        if (level === 'trustedinstaller' && id === 'system') continue
        const connection = this.connections.get(id)
        this.connections.delete(id)
        await connection?.shutdown('replaced')
      }
      return this.state()
    } catch (error) {
      this.lastError = errorText(error)
      throw error
    } finally {
      this.switching = false
    }
  }

  async fsNeedsWorker() {
    return this.needsWorker()
  }

  async fsRequest(op, payload) {
    const level = this.selected
    if (level === this.hostLevel) throw new Error('exec-privilege: direct filesystem path does not use a worker')
    let connection = this.connections.get(level)
    if (connection === undefined || connection.closed) connection = await this.ensureWorker(level)
    if (connection === undefined || connection.closed) throw new Error('执行权限执行器尚未就绪')
    return connection.request(op, payload, 120000)
  }

  async fsStreamText(target) {
    const level = this.selected
    const connection = this.connections.get(level)
    if (connection === undefined || connection.closed) throw new Error('执行权限执行器尚未就绪')
    return connection.streamText(target)
  }

  async fsWatch(target, changed) {
    const level = this.selected
    let connection = this.connections.get(level)
    if (connection === undefined || connection.closed) connection = await this.ensureWorker(level)
    if (connection === undefined || connection.closed) throw new Error('执行权限执行器尚未就绪')
    const entry = { changed }
    const { id, promise } = connection.requestWithId('fs.watch', { target }, 30000)
    connection.watchers.set(id, entry)
    try {
      const result = await promise
      entry.watchId = result?.watchId
    } catch (error) {
      connection.watchers.delete(id)
      throw error
    }
    return async () => {
      connection.watchers.delete(id)
      if (entry.watchId !== undefined) await connection.unwatch(entry.watchId)
    }
  }

  spawnShell(request, realSubprocess) {
    if (this.selected === this.hostLevel) return realSubprocess.spawn(request)
    const connection = this.connections.get(this.selected)
    if (connection === undefined || connection.closed) {
      throw new Error(`执行权限「${LEVEL_BY_ID.get(this.selected)?.labelZh ?? this.selected}」执行器尚未就绪`)
    }
    return connection.spawnShell(request)
  }

  /**
   * The dedicated confirmation surface is the browser client. Every route that
   * can change the level requires the authenticated browser cookie, so a model
   * tool call can create a request but cannot approve it — the user must click
   * Allow in the execution-privilege control.
   */
  rejectUnauthorized(request, response) {
    const connection = this.ctx.get('connection')
    if (connection === undefined) return false
    const rejection = connection.requestRejection?.(request)
    if (rejection === undefined) return false
    response.statusCode = rejection
    response.setHeader('content-type', 'text/plain; charset=utf-8')
    response.setHeader('cache-control', 'no-store')
    response.end('execution privilege: authenticated browser session required\n')
    return true
  }

  createPendingRequest(level, reason, source) {
    const deferred = Promise.withResolvers()
    const request = {
      id: randomUUID(),
      level,
      reason: String(reason ?? '').slice(0, 2000),
      source,
      createdAt: nowIso(),
    }
    this.clearPending({ approved: false, message: '请求已被新的请求取代' })
    this.pendingRequest = request
    this.pendingDecision = deferred
    this.pendingTimer = setTimeout(() => {
      void this.decide(request.id, false).catch(() => {})
    }, 5 * 60 * 1000)
    this.pendingTimer.unref?.()
    return { request, decision: deferred.promise }
  }

  clearPending(result) {
    const deferred = this.pendingDecision
    this.pendingRequest = undefined
    this.pendingDecision = undefined
    if (this.pendingTimer !== undefined) {
      clearTimeout(this.pendingTimer)
      this.pendingTimer = undefined
    }
    deferred?.resolve(result)
  }

  async requestElevation(level, reason, source, signal) {
    await this.ready
    const descriptor = LEVEL_BY_ID.get(level)
    if (descriptor === undefined) throw new Error(`未知执行权限：${level}`)
    const capability = this.capabilities()[level]
    if (!capability?.reachable) {
      throw new Error(capability?.reasonZh || `执行权限「${descriptor.labelZh}」当前不可达`)
    }
    if (level === this.selected) {
      if (this.effective().ready) return { already: true, approved: true, message: `当前已经是「${descriptor.labelZh}」` }
      await this.setLevel(level)
      return { already: true, approved: true, message: `已重新连接「${descriptor.labelZh}」` }
    }
    if (descriptor.rank <= this.rankOf(this.selected)) {
      await this.setLevel(level)
      return { already: false, approved: true, message: `已切换到「${descriptor.labelZh}」` }
    }
    const { request, decision } = this.createPendingRequest(level, reason, source)
    if (signal?.aborted === true) {
      this.clearPending({ approved: false, message: '请求已取消' })
      return { already: false, approved: false, message: '请求已取消' }
    }
    return await new Promise((resolve) => {
      let settled = false
      const onAbort = () => {
        if (this.pendingRequest?.id === request.id) this.clearPending({ approved: false, message: '请求已取消' })
        finish({ already: false, approved: false, message: '请求已取消' })
      }
      const finish = (value) => {
        if (settled) return
        settled = true
        signal?.removeEventListener?.('abort', onAbort)
        resolve(value)
      }
      signal?.addEventListener?.('abort', onAbort, { once: true })
      decision.then(finish, (error) => finish({ already: false, approved: false, message: errorText(error) }))
    })
  }

  async decide(requestId, allow) {
    const request = this.pendingRequest
    if (request === undefined || request.id !== requestId) throw new Error('没有匹配的待确认请求')
    const deferred = this.pendingDecision
    // Hide the prompt before applying so the UI locks immediately.
    this.pendingRequest = undefined
    this.pendingDecision = undefined
    if (this.pendingTimer !== undefined) {
      clearTimeout(this.pendingTimer)
      this.pendingTimer = undefined
    }
    let result
    try {
      if (allow === true) {
        await this.setLevel(request.level, { approvedRequestId: request.id })
        result = {
          approved: true,
          level: request.level,
          message: `用户已批准，执行权限切换为「${LEVEL_BY_ID.get(request.level)?.labelZh ?? request.level}」`,
        }
      } else {
        result = { approved: false, level: request.level, message: '用户拒绝了执行权限提升' }
      }
    } catch (error) {
      this.lastError = errorText(error)
      result = { approved: false, level: request.level, message: errorText(error) }
    }
    deferred?.resolve(result)
    return result
  }

  async handleState(request, response) {
    if (this.rejectUnauthorized(request, response)) return
    try {
      await this.ready
      const body = JSON.stringify(this.state())
      response.statusCode = 200
      response.setHeader('content-type', 'application/json; charset=utf-8')
      response.setHeader('cache-control', 'no-store')
      response.end(body)
    } catch (error) {
      response.statusCode = 500
      response.setHeader('content-type', 'application/json; charset=utf-8')
      response.end(JSON.stringify({ ok: false, error: errorText(error), state: this.state() }))
    }
  }

  async handleLevel(request, response) {
    const send = (status, value) => {
      response.statusCode = status
      response.setHeader('content-type', 'application/json; charset=utf-8')
      response.setHeader('cache-control', 'no-store')
      response.end(JSON.stringify(value))
    }
    if (this.rejectUnauthorized(request, response)) return
    if (request.method !== 'POST') {
      send(405, { ok: false, error: 'only POST is supported' })
      return
    }
    try {
      const body = await readRequestBody(request)
      let payload = {}
      try {
        payload = body.trim() ? JSON.parse(body) : {}
      } catch {
        send(400, { ok: false, error: 'invalid JSON body' })
        return
      }
      const level = String(payload.level ?? '')
      const descriptor = LEVEL_BY_ID.get(level)
      if (descriptor === undefined) {
        send(200, { ok: false, error: `未知执行权限：${level}`, state: this.state() })
        return
      }
      if (descriptor.rank > this.rankOf(this.selected)) {
        send(403, {
          ok: false,
          error: '提升执行权限必须经过专用确认；请使用 /exec-privilege/request 与 /exec-privilege/decision',
          state: this.state(),
        })
        return
      }
      try {
        await this.setLevel(level)
        send(200, { ok: true, state: this.state() })
      } catch (error) {
        send(200, { ok: false, error: errorText(error), state: this.state() })
      }
    } catch (error) {
      send(500, { ok: false, error: errorText(error), state: this.state() })
    }
  }

  async handleRequest(request, response) {
    const send = (status, value) => {
      response.statusCode = status
      response.setHeader('content-type', 'application/json; charset=utf-8')
      response.setHeader('cache-control', 'no-store')
      response.end(JSON.stringify(value))
    }
    if (this.rejectUnauthorized(request, response)) return
    if (request.method !== 'POST') {
      send(405, { ok: false, error: 'only POST is supported' })
      return
    }
    try {
      const body = await readRequestBody(request)
      const payload = body.trim() ? JSON.parse(body) : {}
      const level = String(payload.level ?? '')
      const descriptor = LEVEL_BY_ID.get(level)
      if (descriptor === undefined) {
        send(200, { ok: false, error: `未知执行权限：${level}`, state: this.state() })
        return
      }
      const capability = this.capabilities()[level]
      if (!capability?.reachable) {
        send(200, { ok: false, error: capability?.reasonZh || `执行权限「${descriptor.labelZh}」当前不可达`, state: this.state() })
        return
      }
      if (descriptor.rank <= this.rankOf(this.selected)) {
        await this.setLevel(level)
        send(200, { ok: true, state: this.state() })
        return
      }
      this.createPendingRequest(level, String(payload.reason ?? ''), 'ui')
      send(200, { ok: true, pending: true, state: this.state() })
    } catch (error) {
      send(500, { ok: false, error: errorText(error), state: this.state() })
    }
  }

  async handleDecision(request, response) {
    const send = (status, value) => {
      response.statusCode = status
      response.setHeader('content-type', 'application/json; charset=utf-8')
      response.setHeader('cache-control', 'no-store')
      response.end(JSON.stringify(value))
    }
    if (this.rejectUnauthorized(request, response)) return
    if (request.method !== 'POST') {
      send(405, { ok: false, error: 'only POST is supported' })
      return
    }
    try {
      const body = await readRequestBody(request)
      const payload = body.trim() ? JSON.parse(body) : {}
      const requestId = String(payload.requestId ?? '')
      const allow = payload.decision === 'allow'
      const result = await this.decide(requestId, allow)
      send(200, { ok: true, result, state: this.state() })
    } catch (error) {
      send(200, { ok: false, error: errorText(error), state: this.state() })
    }
  }

  /**
   * Local diagnostic: exercise the actual `ctx.fs` and `ctx.shell` providers at
   * the selected level. It is intentionally not wired into the UI; this proves
   * the privilege routing end to end after a profile reload.
   */
  async handleSelftest(request, response) {
    const send = (status, value) => {
      response.statusCode = status
      response.setHeader('content-type', 'application/json; charset=utf-8')
      response.setHeader('cache-control', 'no-store')
      response.end(JSON.stringify(value))
    }
    if (this.rejectUnauthorized(request, response)) return
    try {
      const url = new URL(request.url ?? '/exec-privilege/selftest', 'http://127.0.0.1')
      const requestedLevel = url.searchParams.get('level')
      if (requestedLevel !== null && requestedLevel !== '' && requestedLevel !== this.selected) {
        send(403, {
          ok: false,
          error: 'the selftest may not switch levels; use the dedicated confirmation flow first',
          state: this.state(),
        })
        return
      }
      await this.ready
      const fsService = this.ctx.get('fs')
      const shellService = this.ctx.get('shell')
      if (fsService === undefined || shellService === undefined) {
        send(503, { ok: false, error: 'ctx.fs / ctx.shell are unavailable', state: this.state() })
        return
      }
      const base = join(CONFIG_DIR, 'selftest')
      fs.mkdirSync(base, { recursive: true })
      const sandboxMode = url.searchParams.get('sandbox') === 'workspace-write' ? 'workspace-write' : 'danger-full-access'
      const workspaceRoot = url.searchParams.get('workspace') || base
      const target = await fsService.resolve(`selftest-${process.pid}-${Date.now()}.txt`, { cwd: base })
      const content = `selftest ${new Date().toISOString()}\n`
      const write = await fsService.writeText(target, content, { kind: 'createIfAbsent' }, undefined)
      const read = await fsService.readText(target, undefined)
      const listing = await fsService.listDir(await fsService.resolve('.', { cwd: base }), undefined)
      const execution = await shellService.execute(shellService.resolve({
        command: 'whoami /user /groups /fo list',
        workdir: workspaceRoot,
        sandboxPolicy: { mode: sandboxMode, workspaceRoot },
      }))
      const result = await execution.result()
      send(200, {
        ok: true,
        level: this.selected,
        effective: this.effective(),
        providers: {
          fs: fsService.constructor?.name,
          shell: shellService.constructor?.name,
        },
        fs: {
          writeOperation: write?.operation,
          readMatches: read === content,
          listingEntries: Array.isArray(listing) ? listing.length : null,
        },
        shell: {
          exitCode: result.exitCode,
          signal: result.signal,
          timedOut: result.timedOut,
          sandbox: result.sandbox ?? null,
          stdout: result.stdout?.text?.slice(0, 8000),
          stderr: result.stderr?.text?.slice(0, 4000),
        },
      })
    } catch (error) {
      send(200, { ok: false, error: errorText(error), state: this.state() })
    }
  }
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = ''
    request.setEncoding('utf8')
    request.on('data', (chunk) => {
      body += chunk
      if (body.length > 1024 * 1024) {
        reject(new Error('request body too large'))
        request.destroy()
      }
    })
    request.on('end', () => resolve(body))
    request.on('error', reject)
  })
}

/**
 * Register the execution-privilege service as `ctx.execPrivilege` for the
 * shelf and shell providers and for the Web UI routes.
 * @param {import('@deepseek-ai/cordis').Context} ctx - profile context.
 */
export function apply(ctx) {
  const service = new ExecPrivilegeService(ctx)
  const unprovide = ctx.provide('execPrivilege', service)
  ctx.effect(() => () => {
    service.dispose()
    unprovide()
  }, 'exec-privilege: service lifecycle')

  // Dedicated confirmation tool. It only creates a request; the approval
  // itself lives in the execution-privilege control, which is cookie-bound to
  // the user's browser. The call resolves with the user's decision.
  const { defineTool } = loadPackage(service.runtimeDir, '@deepseek-ai/dsh-tools')
  ctx.effect(() => ctx.tools.register(defineTool({
    name: 'request_exec_privilege',
    description: [
      'Request permission to run the file and terminal tools at a different Windows execution privilege.',
      'This tool only asks the user: it never elevates by itself, and it cannot approve its own request.',
      'The user must approve in the dedicated "Execution privilege" control; the call resolves with that decision.',
      'Use it only when the task genuinely requires another level, and never to bypass a denial.',
    ].join(' '),
    parameters: {
      level: {
        type: 'string',
        required: true,
        enum: ['user', 'admin', 'system', 'trustedinstaller'],
        description: 'Target execution privilege: user, admin, system, or trustedinstaller.',
      },
      reason: {
        type: 'string',
        required: true,
        description: 'One sentence for the user explaining why this task needs that level. Use the language of the current user request.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          level: { type: 'string', required: true },
          approved: { type: 'boolean', required: true },
          already: { type: 'boolean' },
          message: { type: 'string' },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.already === true
          ? `Execution privilege is already ${value.level}.`
          : value.approved === true
            ? `The user approved running tools as ${value.level}.`
            : `The user did not approve running tools as ${value.level}: ${value.message ?? 'denied'}`,
      }],
    },
    async execute(args, exec) {
      const level = String(args.level ?? '')
      const reason = String(args.reason ?? '')
      const result = await service.requestElevation(level, reason, 'model', exec.signal)
      return {
        level,
        approved: result.approved === true,
        already: result.already === true,
        message: result.message ?? '',
      }
    },
  })), 'exec-privilege: request_exec_privilege tool')
}
