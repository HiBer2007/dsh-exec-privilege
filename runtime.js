// @local/dsh-exec-privilege/runtime
//
// Locate the DSH runtime package tree that the current Host was booted from,
// and load its classes without adding a dependency edge to the profile.
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, basename } from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

export const pluginDir = dirname(fileURLToPath(import.meta.url))

function looksLikeRuntime(dir) {
  return (
    typeof dir === 'string' &&
    dir.length > 0 &&
    existsSync(join(dir, 'node_modules', '@deepseek-ai', 'dsh-fs-sandbox', 'package.json'))
  )
}

/**
 * Resolve the DSH runtime directory (`.../dsh`, the parent of its
 * `node_modules`). Candidates come from the Host argv, the Electron
 * installation layout, and an explicit environment override.
 * @returns {string|undefined} absolute runtime directory.
 */
export function findRuntimeDir() {
  const candidates = []
  if (process.env.DSH_EXEC_PRIVILEGE_RUNTIME_DIR) candidates.push(process.env.DSH_EXEC_PRIVILEGE_RUNTIME_DIR)
  if (process.env.DSH_DESKTOP_DSH_DIR) candidates.push(process.env.DSH_DESKTOP_DSH_DIR)

  // Desktop host: argv[2] is the runtime directory; CLI: argv[1] is an entry
  // inside <runtime>/node_modules/@deepseek-ai/<package>/...
  const argv = process.argv
  if (argv[2] && looksLikeRuntime(argv[2])) candidates.push(argv[2])
  for (const entry of [argv[1], argv[2]]) {
    if (!entry) continue
    let current = dirname(entry)
    for (let depth = 0; depth < 12; depth += 1) {
      if (basename(current) === 'node_modules') {
        candidates.push(dirname(current))
        break
      }
      if (basename(current) === '@deepseek-ai') {
        candidates.push(dirname(dirname(current)))
        break
      }
      const parent = dirname(current)
      if (parent === current) break
      current = parent
    }
  }

  // Packaged Electron layout: <exe dir>/resources/app.asar/dsh.
  const exeDir = dirname(process.execPath)
  for (const resources of [join(exeDir, 'resources'), join(exeDir, '..', 'resources')]) {
    const asarDsh = join(resources, 'app.asar', 'dsh')
    if (looksLikeRuntime(asarDsh)) candidates.push(asarDsh)
  }

  // A `dsh` package inside a normal node_modules tree.
  try {
    const req = createRequire(join(pluginDir, 'package.json'))
    const resolved = req.resolve('@deepseek-ai/dsh/package.json')
    const runtime = dirname(dirname(resolved))
    if (looksLikeRuntime(runtime)) candidates.push(runtime)
  } catch {}

  for (const candidate of candidates) {
    if (looksLikeRuntime(candidate)) return candidate
  }
  return undefined
}

/**
 * Build a require anchored at the runtime package tree so modules inside the
 * app.asar resolve exactly as the Host sees them.
 * @param {string} runtimeDir absolute runtime directory.
 */
export function runtimeRequire(runtimeDir) {
  return createRequire(join(runtimeDir, 'package.json'))
}

/**
 * Load one runtime package's CommonJS/ESM namespace through the runtime's own
 * resolver. Node's require(esm) support returns the module namespace object.
 * @param {string} runtimeDir absolute runtime directory.
 * @param {string} specifier package name.
 */
export function loadPackage(runtimeDir, specifier) {
  const req = runtimeRequire(runtimeDir)
  return req(specifier)
}

export function readJson(file) {
  return JSON.parse(readFileSync(file, 'utf8'))
}
