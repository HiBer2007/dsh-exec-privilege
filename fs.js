// @local/dsh-exec-privilege/fs
//
// `ctx.fs` provider that keeps the shipped `SandboxedFileSystem` policy seam
// (read-only / workspace-write / full-access containment) but executes the
// actual file operations inside the selected privilege worker.
import { findRuntimeDir, loadPackage } from './runtime.js'

const runtimeDir = findRuntimeDir()
if (!runtimeDir) throw new Error('exec-privilege/fs: cannot locate the DSH runtime directory')
const { SandboxedFileSystem } = loadPackage(runtimeDir, '@deepseek-ai/dsh-fs-sandbox')
const { FsError } = loadPackage(runtimeDir, '@deepseek-ai/dsh-fs')

function asFsError(error) {
  if (error instanceof FsError) return error
  if (error && typeof error === 'object' && typeof error.code === 'string' && error.code.startsWith('FS_')) {
    return new FsError(error.message ?? String(error), error.code, { cause: error })
  }
  return new FsError(error instanceof Error ? error.message : String(error), 'FS_IO_ERROR', { cause: error })
}

function throwIfAborted(signal, verb) {
  if (signal?.aborted) throw new FsError(`${verb} aborted`, 'FS_ABORTED')
}

/**
 * Filesystem backend that routes reads/writes through the selected
 * execution-privilege worker while retaining the sandbox fence.
 */
export default class PrivilegedFileSystem extends SandboxedFileSystem {
  static inject = ['sandboxPolicy', 'execPrivilege']

  constructor(ctx, config) {
    super(ctx, config)
  }

  get routed() {
    return this.ctx.execPrivilege.needsWorker()
  }

  async call(op, payload) {
    try {
      return await this.ctx.execPrivilege.fsRequest(op, payload)
    } catch (error) {
      throw asFsError(error)
    }
  }

  async resolve(path, opts) {
    throwIfAborted(opts?.signal, 'resolve')
    if (!this.routed) return super.resolve(path, opts)
    const result = await this.call('fs.resolve', { path, cwd: opts?.cwd ?? this.config.cwd })
    throwIfAborted(opts?.signal, 'resolve')
    return result
  }

  async stat(target, signal) {
    throwIfAborted(signal, 'stat')
    if (!this.routed) return super.stat(target, signal)
    const result = await this.call('fs.stat', { target })
    throwIfAborted(signal, 'stat')
    return result
  }

  async lstat(path, opts, signal) {
    throwIfAborted(signal, 'lstat')
    if (!this.routed) return super.lstat(path, opts, signal)
    const result = await this.call('fs.lstat', { path, cwd: opts?.cwd ?? this.config.cwd })
    throwIfAborted(signal, 'lstat')
    return result
  }

  async readText(target, signal) {
    throwIfAborted(signal, 'read')
    if (!this.routed) return super.readText(target, signal)
    const result = await this.call('fs.readText', { target })
    throwIfAborted(signal, 'read')
    return result
  }

  streamText(target, signal) {
    if (!this.routed) return super.streamText(target, signal)
    if (signal?.aborted) return Promise.reject(new FsError('read aborted', 'FS_ABORTED'))
    const source = this.ctx.execPrivilege.fsStreamText(target)
    return (async function* stream() {
      for await (const chunk of await source) {
        if (signal?.aborted) throw new FsError('read aborted', 'FS_ABORTED')
        yield typeof chunk === 'string' ? chunk : chunk?.text ?? ''
      }
    })()
  }

  async readBytes(target, signal, maxBytes) {
    throwIfAborted(signal, 'read')
    if (!this.routed) return super.readBytes(target, signal, maxBytes)
    const result = await this.call('fs.readBytes', { target, maxBytes })
    throwIfAborted(signal, 'read')
    return Buffer.from(result.data, 'base64')
  }

  async readByteRange(target, range, signal) {
    throwIfAborted(signal, 'read')
    if (!this.routed) return super.readByteRange(target, range, signal)
    const result = await this.call('fs.readByteRange', { target, range })
    throwIfAborted(signal, 'read')
    return Buffer.from(result.data, 'base64')
  }

  async listDir(target, signal) {
    throwIfAborted(signal, 'list')
    if (!this.routed) return super.listDir(target, signal)
    const result = await this.call('fs.listDir', { target })
    throwIfAborted(signal, 'list')
    return result
  }

  async writeText(target, content, expected, signal, sandboxPolicy) {
    // Direct mode must hand the ORIGINAL policy to the parent: calling
    // checkedTarget here and then super.writeText(checked, ...) would re-run
    // the fence without a policy and fall back to the deployment default,
    // denying writes the session explicitly allows.
    if (!this.routed) return super.writeText(target, content, expected, signal, sandboxPolicy)
    const checked = await this.checkedTarget(target, sandboxPolicy)
    throwIfAborted(signal, 'write')
    const result = await this.call('fs.writeText', { target: checked, content, expected })
    throwIfAborted(signal, 'write')
    return result
  }

  async editText(target, edit, expected, signal, sandboxPolicy) {
    if (!this.routed) return super.editText(target, edit, expected, signal, sandboxPolicy)
    const checked = await this.checkedTarget(target, sandboxPolicy)
    throwIfAborted(signal, 'edit')
    const result = await this.call('fs.editText', { target: checked, edit, expected })
    throwIfAborted(signal, 'edit')
    return result
  }

  async watch(target, changed, signal) {
    if (!this.routed) return super.watch(target, changed, signal)
    throwIfAborted(signal, 'watch')
    return this.ctx.execPrivilege.fsWatch(target, changed)
  }
}
