// @local/dsh-exec-privilege/shell
//
// `ctx.shell` provider that keeps the shipped sandboxed PowerShell executor
// (policy resolution, ACL confinement argv, denial classification) but spawns
// the resulting argv inside the selected privilege worker.
import { findRuntimeDir, loadPackage } from './runtime.js'

const runtimeDir = findRuntimeDir()
if (!runtimeDir) throw new Error('exec-privilege/shell: cannot locate the DSH runtime directory')
const { SandboxPwshExecutor } = loadPackage(runtimeDir, '@deepseek-ai/dsh-pwsh-sandbox')
const baseExecuteArgv = Object.getPrototypeOf(SandboxPwshExecutor.prototype).executeArgv

/**
 * Sandbox-aware executor whose only changed step is the subprocess spawn
 * target. Direct execution is used when the selected level equals the Host's
 * own token; otherwise the worker connection owns the process.
 */
export default class PrivilegedPwshExecutor extends SandboxPwshExecutor {
  static inject = ['subprocess', 'sandbox', 'sandboxPolicy', 'execPrivilege']

  executeArgv(spec, argvOrPrepare, onStarted) {
    const realSubprocess = this.ctx.subprocess
    // The Cordis service instance is a proxy with a rejecting `ctx` setter;
    // define the facade's own properties instead of assigning through it.
    const facade = Object.create(this, {
      ctx: {
        value: {
          subprocess: {
            spawn: (request) => this.ctx.execPrivilege.spawnShell(request, realSubprocess),
          },
        },
        writable: true,
        configurable: true,
        enumerable: true,
      },
      config: { value: this.config, writable: true, configurable: true },
      processFacts: { value: this.processFacts, writable: true, configurable: true },
      declaredPwshPath: { value: this.declaredPwshPath, writable: true, configurable: true },
      resolvedPwshPath: { value: this.resolvedPwshPath, writable: true, configurable: true },
    })
    return baseExecuteArgv.call(facade, spec, argvOrPrepare, onStarted)
  }
}
