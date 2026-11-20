// @local/dsh-exec-privilege/worker
//
// Out-of-process executor for one Windows privilege level. It connects back to
// the DSH host over loopback (token-authenticated), then serves shell and
// filesystem operations with its own token. The host never falls back to its
// own privilege when this worker is selected.

'use strict'

const fs = require('node:fs')
const path = require('node:path')
const net = require('node:net')
const os = require('node:os')
const { spawn } = require('node:child_process')
const { createRequire } = require('node:module')
const native = require('./native.cjs')

const MAX_LINE_BYTES = 256 * 1024 * 1024
const CONNECT_RETRY_MS = 250
const CONNECT_TIMEOUT_MS = 45000

let config
let socket
let hostBuffer = ''
let localFs
let logStream
const shellProcesses = new Map()
const watchers = new Map()
const streamCancels = new Map()
let shuttingDown = false

function log(line) {
  const text = `${new Date().toISOString()} ${line}\n`
  try {
    if (!logStream) logStream = fs.createWriteStream(config.logPath, { flags: 'a' })
    logStream.write(text)
  } catch {}
  if (process.env.DSH_EXEC_PRIVILEGE_DEBUG === '1') process.stderr.write(text)
}

function loadConfig() {
  const index = process.argv.indexOf('--config')
  const file = index >= 0 ? process.argv[index + 1] : process.argv[2]
  if (!file) throw new Error('exec-privilege worker: missing --config')
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'))
  if (!parsed.port || !parsed.token || !parsed.runtimeDir || !parsed.workerScript) {
    throw new Error('exec-privilege worker: incomplete config')
  }
  return parsed
}

function send(message) {
  if (!socket || socket.destroyed) return
  try {
    socket.write(`${JSON.stringify(message)}\n`)
  } catch (error) {
    log(`send failed: ${error instanceof Error ? error.message : String(error)}`)
  }
}

function ok(id, value) {
  send({ type: 'response', id, ok: true, value })
}

function fail(id, error) {
  const payload = {
    name: error?.name ?? 'Error',
    message: error instanceof Error ? error.message : String(error),
    code: error?.code,
    cause: error?.cause instanceof Error ? error.cause.message : undefined,
  }
  send({ type: 'response', id, ok: false, error: payload })
}

function createFileSystem() {
  const req = createRequire(path.join(config.runtimeDir, 'package.json'))
  const { LocalFileSystem } = req(path.join(config.runtimeDir, 'node_modules', '@deepseek-ai', 'dsh-fs-local'))
  const stub = {
    // Service's constructor only needs a registration sink; the worker never
    // resolves any other service through this stub.
    reflect: { provide() {} },
  }
  return new LocalFileSystem(stub, {
    cwd: config.cwd,
    diffBasisMaxBytes: config.diffBasisMaxBytes ?? 10 * 1024 * 1024,
  })
}

function scrubbedEnv() {
  try {
    const req = createRequire(path.join(config.runtimeDir, 'package.json'))
    const { scrubbedParentEnv } = req('@deepseek-ai/dsh-subprocess')
    if (typeof scrubbedParentEnv === 'function') return scrubbedParentEnv()
  } catch {}
  return { ...process.env }
}

function describeIdentity() {
  try {
    const info = native.inspectToken(config.runtimeDir)
    return {
      pid: process.pid,
      userSid: info.userSid,
      userName: info.userName,
      integrity: info.integrity,
      integritySid: info.integritySid,
      elevationType: info.elevationType,
      elevated: info.elevated,
      sessionId: info.sessionId,
      isAdmin: info.isAdmin,
      isSystem: info.isSystem,
      isTrustedInstaller: info.isTrustedInstaller,
    }
  } catch (error) {
    return {
      pid: process.pid,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

function terminateProcessTree(pid) {
  try {
    const outcome = spawn('C:\\Windows\\System32\\taskkill.exe', ['/PID', String(pid), '/T', '/F'], {
      windowsHide: true,
      stdio: 'ignore',
    })
    outcome.on('error', () => {})
  } catch {}
}

function wireShell(record) {
  const { child, id, stdoutMaxBytes, stderrMaxBytes, spillMaxBytes } = record
  const limits = new Map([
    ['stdout', stdoutMaxBytes],
    ['stderr', stderrMaxBytes],
  ])
  const spillFiles = new Map()
  const spillStreams = new Map()
  const totals = { stdout: 0, stderr: 0 }

  const ensureSpill = (stream) => {
    if (spillMaxBytes <= 0) return undefined
    if (spillFiles.has(stream)) return spillFiles.get(stream)
    const name = `exec-priv-${process.pid}-${id}-${stream}.log`
    const file = path.join(config.spillDir, name)
    try {
      spillStreams.set(stream, fs.createWriteStream(file, { flags: 'a' }))
      spillFiles.set(stream, file)
      send({ type: 'event', id, event: 'spill', stream, path: file })
      return file
    } catch (error) {
      log(`spill create failed: ${error instanceof Error ? error.message : String(error)}`)
      return undefined
    }
  }

  const onData = (stream, chunk) => {
    if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk)
    const total = totals[stream]
    totals[stream] = total + chunk.length
    send({ type: 'event', id, event: stream, data: chunk.toString('base64') })
    const limit = limits.get(stream) ?? 0
    const spillLimit = spillMaxBytes
    if (spillLimit > 0) {
      const file = ensureSpill(stream)
      const streamWriter = spillStreams.get(stream)
      if (file && streamWriter) {
        const already = streamWriter.bytesWritten ?? 0
        if (already < spillLimit) {
          const writable = chunk.subarray(0, Math.max(0, spillLimit - already))
          if (writable.length > 0) streamWriter.write(writable)
        }
      }
    }
    // Keep the model-visible in-memory window bounded on the host; the host
    // reader enforces its own cap. Nothing else is dropped here.
    void limit
  }

  child.stdout?.on('data', (chunk) => onData('stdout', chunk))
  child.stderr?.on('data', (chunk) => onData('stderr', chunk))
  child.on('error', (error) => {
    send({ type: 'event', id, event: 'error', message: error instanceof Error ? error.message : String(error) })
  })
  child.on('close', (exitCode, signal) => {
    for (const writer of spillStreams.values()) {
      try {
        writer.end()
      } catch {}
    }
    shellProcesses.delete(id)
    send({ type: 'event', id, event: 'exit', exitCode: exitCode ?? null, signal: signal ?? null })
  })
}

function shellSpawn(id, request) {
  const argv = Array.isArray(request.argv) ? request.argv : []
  if (argv.length === 0) throw new Error('shell.spawn requires argv')
  const env = scrubbedEnv()
  for (const [key, value] of Object.entries(request.env ?? {})) {
    if (value === undefined) delete env[key]
    else env[key] = String(value)
  }
  const child = spawn(argv[0], argv.slice(1), {
    cwd: request.cwd ?? config.cwd,
    env,
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  const record = {
    child,
    id,
    stdoutMaxBytes: Number(request.stdoutMaxBytes) || 65536,
    stderrMaxBytes: Number(request.stderrMaxBytes) || 65536,
    spillMaxBytes: Number(request.spillMaxBytes) || 0,
  }
  shellProcesses.set(id, record)
  wireShell(record)
  if (typeof request.stdin === 'string' && request.stdin.length > 0) {
    try {
      child.stdin.write(request.stdin, 'utf8')
    } catch {}
  }
  try {
    child.stdin.end()
  } catch {}
  ok(id, { pid: child.pid })
}

function shellKill(id, request) {
  const record = shellProcesses.get(request?.shellId ?? id)
  if (record) {
    if (record.child.pid) terminateProcessTree(record.child.pid)
    try {
      record.child.kill('SIGKILL')
    } catch {}
    ok(id, { killed: true })
    return
  }
  if (request?.pid) terminateProcessTree(request.pid)
  ok(id, { killed: false })
}

function watchTarget(id, request) {
  const watchId = `${process.pid}:${id}`
  try {
    localFs
      .watch(request.target, (error) => {
        send({
          type: 'watch',
          id,
          event: error ? 'error' : 'changed',
          ...(error ? { message: error instanceof Error ? error.message : String(error) } : {}),
        })
      }, new AbortController().signal)
      .then((close) => {
        watchers.set(watchId, close)
        ok(id, { watchId })
      })
      .catch((error) => fail(id, error))
  } catch (error) {
    fail(id, error)
  }
}

async function streamText(id, request) {
  const iterator = await localFs.streamText(request.target, undefined)
  let closed = false
  streamCancels.set(id, () => {
    closed = true
  })
  try {
    for await (const chunk of iterator) {
      if (closed || shuttingDown) break
      if (typeof chunk === 'string' && chunk.length > 0) send({ type: 'stream', id, text: chunk })
    }
    send({ type: 'stream-end', id, error: null })
  } catch (error) {
    send({ type: 'stream-end', id, error: { name: error?.name, message: error instanceof Error ? error.message : String(error), code: error?.code } })
  } finally {
    streamCancels.delete(id)
  }
}

function launchLevelWorker(id, request) {
  if (request.level !== 'trustedinstaller') throw new Error(`unsupported worker level: ${request.level}`)
  const duplicate = native.duplicateTrustedInstallerToken(config.runtimeDir)
  try {
    const command = `"C:\\Windows\\System32\\cmd.exe" /c set "ELECTRON_RUN_AS_NODE=1"&& "${config.exePath}" "${config.workerScript}" --config "${request.configPath}"`
    const child = native.launchWithToken(config.runtimeDir, duplicate.token, command, {
      cwd: config.cwd,
      creationFlags: 0,
    })
    // Closing the parent handle does not stop the target process.
    child.close()
    ok(id, { pid: child.pid })
  } finally {
    duplicate.close()
  }
}

async function handleRequest(message) {
  const { id, op } = message
  try {
    switch (op) {
      case 'ping':
        ok(id, { pong: true, level: config.level })
        return
      case 'shutdown':
        ok(id, { bye: true })
        setTimeout(() => cleanupAndExit(0), 30)
        return
      case 'shell.spawn':
        shellSpawn(id, message)
        return
      case 'shell.kill':
        shellKill(id, message)
        return
      case 'fs.resolve': {
        const target = await localFs.resolve(message.path, { cwd: message.cwd ?? config.cwd })
        ok(id, target)
        return
      }
      case 'fs.stat': {
        ok(id, await localFs.stat(message.target, undefined))
        return
      }
      case 'fs.lstat': {
        ok(id, await localFs.lstat(message.path, { cwd: message.cwd ?? config.cwd }, undefined))
        return
      }
      case 'fs.readText': {
        ok(id, await localFs.readText(message.target, undefined))
        return
      }
      case 'fs.readBytes': {
        const bytes = await localFs.readBytes(message.target, undefined, message.maxBytes)
        ok(id, { data: Buffer.from(bytes).toString('base64') })
        return
      }
      case 'fs.readByteRange': {
        const bytes = await localFs.readByteRange(message.target, message.range, undefined)
        ok(id, { data: Buffer.from(bytes).toString('base64') })
        return
      }
      case 'fs.listDir': {
        ok(id, await localFs.listDir(message.target, undefined))
        return
      }
      case 'fs.writeText': {
        ok(id, await localFs.writeText(message.target, message.content, message.expected, undefined))
        return
      }
      case 'fs.editText': {
        ok(id, await localFs.editText(message.target, message.edit, message.expected, undefined))
        return
      }
      case 'fs.watch':
        watchTarget(id, message)
        return
      case 'fs.unwatch': {
        const close = watchers.get(message.watchId)
        if (close) {
          watchers.delete(message.watchId)
          try {
            await close()
          } catch {}
        }
        ok(id, { closed: Boolean(close) })
        return
      }
      case 'fs.streamText':
        await streamText(id, message)
        return
      case 'spawn-worker':
        launchLevelWorker(id, message)
        return
      default:
        throw new Error(`unknown op: ${String(op)}`)
    }
  } catch (error) {
    fail(id, error)
  }
}

function handleLine(line) {
  if (line.length === 0) return
  let message
  try {
    message = JSON.parse(line)
  } catch (error) {
    log(`bad json: ${error instanceof Error ? error.message : String(error)}`)
    return
  }
  if (!message || typeof message !== 'object') return
  if (message.type === 'request') {
    void handleRequest(message)
    return
  }
  if (message.type === 'shutdown') {
    cleanupAndExit(0)
  }
}

function onSocketData(chunk) {
  hostBuffer += chunk.toString('utf8')
  if (hostBuffer.length > MAX_LINE_BYTES) {
    log('incoming message too large; closing')
    cleanupAndExit(1)
    return
  }
  let index
  while ((index = hostBuffer.indexOf('\n')) >= 0) {
    const line = hostBuffer.slice(0, index)
    hostBuffer = hostBuffer.slice(index + 1)
    handleLine(line)
  }
}

function cleanupAndExit(code) {
  if (shuttingDown) return
  shuttingDown = true
  for (const record of shellProcesses.values()) {
    if (record.child.pid) terminateProcessTree(record.child.pid)
    try {
      record.child.kill('SIGKILL')
    } catch {}
  }
  shellProcesses.clear()
  for (const close of watchers.values()) {
    try {
      void close()
    } catch {}
  }
  watchers.clear()
  for (const cancel of streamCancels.values()) {
    try {
      cancel()
    } catch {}
  }
  streamCancels.clear()
  try {
    socket?.end()
  } catch {}
  setTimeout(() => {
    try {
      logStream?.end()
    } catch {}
    process.exit(code)
  }, 120)
  setTimeout(() => process.exit(code), 900).unref()
}

function connect() {
  const deadline = Date.now() + CONNECT_TIMEOUT_MS
  const attempt = () => {
    if (shuttingDown) return
    const candidate = net.connect({ host: '127.0.0.1', port: config.port }, () => {
      socket = candidate
      socket.setNoDelay(true)
      socket.setEncoding('utf8')
      socket.on('data', (chunk) => onSocketData(chunk))
      socket.on('error', (error) => log(`socket error: ${error.message}`))
      socket.on('close', () => {
        if (!shuttingDown) cleanupAndExit(0)
      })
      send({
        type: 'hello',
        token: config.token,
        level: config.level,
        pid: process.pid,
        identity: describeIdentity(),
        execPath: process.execPath,
        cwd: process.cwd(),
      })
      log(`connected as ${config.level}`)
      if (config.taskName) {
        // A SYSTEM task can clean up its own task definition.
        try {
          spawn('C:\\Windows\\System32\\schtasks.exe', ['/Delete', '/TN', config.taskName, '/F'], {
            windowsHide: true,
            stdio: 'ignore',
          }).on('error', () => {})
        } catch {}
      }
    })
    candidate.on('error', () => {
      candidate.destroy()
      if (Date.now() >= deadline || shuttingDown) {
        log('connect timed out')
        process.exit(2)
      }
      setTimeout(attempt, CONNECT_RETRY_MS)
    })
  }
  attempt()
}

function main() {
  config = loadConfig()
  try {
    fs.mkdirSync(config.spillDir, { recursive: true })
  } catch {}
  try {
    fs.mkdirSync(path.dirname(config.logPath), { recursive: true })
  } catch {}
  log(`worker start level=${config.level} pid=${process.pid}`)
  localFs = createFileSystem()
  connect()
  process.on('uncaughtException', (error) => {
    log(`uncaught exception: ${error instanceof Error ? error.stack ?? error.message : String(error)}`)
  })
  process.on('unhandledRejection', (reason) => {
    log(`unhandled rejection: ${reason instanceof Error ? reason.stack ?? reason.message : String(reason)}`)
  })
  process.on('SIGTERM', () => cleanupAndExit(0))
  process.on('SIGINT', () => cleanupAndExit(0))
}

main()
