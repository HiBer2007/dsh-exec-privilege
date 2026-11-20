// @local/dsh-exec-privilege/native
//
// Win32 token + process primitives for the execution-privilege feature.
// CommonJS so both the ESM host plugin and the CJS worker can load it through
// the DSH runtime's own koffi installation.
//
// Verified against Windows 11 22631:
//   - SAFER normal-user token (admin SIDs deny-only) lowered to Medium IL is
//     accepted by CreateProcessAsUserW from an elevated host.
//   - The TrustedInstaller service process token can only be duplicated with
//     TOKEN_DUPLICATE by a SYSTEM caller; the resulting token carries the
//     NT SERVICE\TrustedInstaller group and can write TI-protected paths.
//   - A SYSTEM scheduled task can start the helper, which then duplicates the
//     TI token and launches the TI worker.
const path = require('node:path')
const fs = require('node:fs')
const { createRequire } = require('node:module')
const { execFileSync, spawnSync } = require('node:child_process')

const SID_SYSTEM = 'S-1-5-18'
const SID_ADMINISTRATORS = 'S-1-5-32-544'
const SID_TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
const SID_INTEGRITY_LOW = 'S-1-16-4096'
const SID_INTEGRITY_MEDIUM = 'S-1-16-8192'
const SID_INTEGRITY_HIGH = 'S-1-16-12288'
const SID_INTEGRITY_SYSTEM = 'S-1-16-16384'
const SID_INTEGRITY_PROTECTED = 'S-1-16-20480'

const TOKEN_QUERY = 0x0008
const TOKEN_DUPLICATE = 0x0002
const TOKEN_ASSIGN_PRIMARY = 0x0001
const TOKEN_ADJUST_DEFAULT = 0x0080
const TOKEN_ADJUST_PRIVILEGES = 0x0020
const TOKEN_ADJUST_SESSIONID = 0x0100
const TOKEN_ALL_ACCESS = 0xf01ff
const MAXIMUM_ALLOWED = 0x02000000
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
const PROCESS_QUERY_INFORMATION = 0x0400
const PROCESS_ALL_ACCESS = 0x1f0fff
const SE_PRIVILEGE_ENABLED = 0x00000002
const ERROR_NOT_ALL_ASSIGNED = 1300
const ERROR_INSUFFICIENT_BUFFER = 122

let cached

function isWindows() {
  return process.platform === 'win32'
}

function requireKoffi(runtimeDir) {
  return createRequire(path.join(runtimeDir, 'package.json'))('koffi')
}

function bindings(runtimeDir) {
  if (cached !== undefined) return cached
  if (!isWindows()) throw new Error('exec-privilege: native Win32 bindings are only available on Windows')
  const koffi = requireKoffi(runtimeDir)
  const PVOID = koffi.pointer('void')
  const PPVOID = koffi.pointer(PVOID)
  const HANDLE = PVOID

  const STARTUPINFOW = koffi.struct('DSH_EP_STARTUPINFOW', {
    cb: 'uint32',
    lpReserved: 'str16',
    lpDesktop: 'str16',
    lpTitle: 'str16',
    dwX: 'uint32',
    dwY: 'uint32',
    dwXSize: 'uint32',
    dwYSize: 'uint32',
    dwXCountChars: 'uint32',
    dwYCountChars: 'uint32',
    dwFillAttribute: 'uint32',
    dwFlags: 'uint32',
    wShowWindow: 'uint16',
    cbReserved2: 'uint16',
    lpReserved2: koffi.pointer('uint8'),
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
  })
  const PROCESS_INFORMATION = koffi.struct('DSH_EP_PROCESS_INFORMATION', {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: 'uint32',
    dwThreadId: 'uint32',
  })
  const LUID = koffi.struct('DSH_EP_LUID', { LowPart: 'uint32', HighPart: 'int32' })
  const LUID_AND_ATTRIBUTES = koffi.struct('DSH_EP_LUID_AND_ATTRIBUTES', {
    Luid: LUID,
    Attributes: 'uint32',
  })
  const TOKEN_PRIVILEGES = koffi.struct('DSH_EP_TOKEN_PRIVILEGES', {
    PrivilegeCount: 'uint32',
    Privileges: koffi.array(LUID_AND_ATTRIBUTES, 1),
  })
  if (STARTUPINFOW.size !== 104) throw new Error(`exec-privilege: STARTUPINFOW layout mismatch (${STARTUPINFOW.size})`)
  if (PROCESS_INFORMATION.size !== 24) throw new Error(`exec-privilege: PROCESS_INFORMATION layout mismatch (${PROCESS_INFORMATION.size})`)

  const kernel32 = koffi.load('kernel32.dll')
  const advapi32 = koffi.load('advapi32.dll')
  const wtsapi32 = koffi.load('wtsapi32.dll')
  const bind = (lib, name, result, args) => lib.func('__stdcall', name, result, args)

  const api = {
    koffi,
    PVOID,
    PPVOID,
    HANDLE,
    STARTUPINFOW,
    PROCESS_INFORMATION,
    LUID,
    TOKEN_PRIVILEGES,
    getCurrentProcess: bind(kernel32, 'GetCurrentProcess', HANDLE, []),
    getCurrentProcessId: bind(kernel32, 'GetCurrentProcessId', 'uint32', []),
    closeHandle: bind(kernel32, 'CloseHandle', 'int', [HANDLE]),
    getLastError: bind(kernel32, 'GetLastError', 'uint32', []),
    formatMessageW: bind(kernel32, 'FormatMessageW', 'uint32', [
      'uint32',
      PVOID,
      'uint32',
      'uint32',
      PVOID,
      'uint32',
      PVOID,
    ]),
    openProcess: bind(kernel32, 'OpenProcess', HANDLE, ['uint32', 'int', 'uint32']),
    waitForSingleObject: bind(kernel32, 'WaitForSingleObject', 'uint32', [HANDLE, 'uint32']),
    getExitCodeProcess: bind(kernel32, 'GetExitCodeProcess', 'int', [HANDLE, koffi.pointer('uint32')]),
    terminateProcess: bind(kernel32, 'TerminateProcess', 'int', [HANDLE, 'uint32']),
    createProcessAsUserW: bind(advapi32, 'CreateProcessAsUserW', 'int', [
      HANDLE,
      'str16',
      'str16',
      PVOID,
      PVOID,
      'int',
      'uint32',
      PVOID,
      'str16',
      koffi.pointer(STARTUPINFOW),
      koffi.pointer(PROCESS_INFORMATION),
    ]),
    createProcessWithTokenW: bind(advapi32, 'CreateProcessWithTokenW', 'int', [
      HANDLE,
      'uint32',
      'str16',
      'str16',
      'uint32',
      PVOID,
      'str16',
      koffi.pointer(STARTUPINFOW),
      koffi.pointer(PROCESS_INFORMATION),
    ]),
    openProcessToken: bind(advapi32, 'OpenProcessToken', 'int', [HANDLE, 'uint32', PPVOID]),
    getTokenInformation: bind(advapi32, 'GetTokenInformation', 'int', [
      HANDLE,
      'int',
      PVOID,
      'uint32',
      koffi.pointer('uint32'),
    ]),
    setTokenInformation: bind(advapi32, 'SetTokenInformation', 'int', [HANDLE, 'int', PVOID, 'uint32']),
    duplicateTokenEx: bind(advapi32, 'DuplicateTokenEx', 'int', [
      HANDLE,
      'uint32',
      PVOID,
      'int',
      'int',
      PPVOID,
    ]),
    adjustTokenPrivileges: bind(advapi32, 'AdjustTokenPrivileges', 'int', [
      HANDLE,
      'int',
      koffi.pointer(TOKEN_PRIVILEGES),
      'uint32',
      PVOID,
      PVOID,
    ]),
    lookupPrivilegeValueW: bind(advapi32, 'LookupPrivilegeValueW', 'int', [
      'str16',
      'str16',
      koffi.pointer(LUID),
    ]),
    convertSidToStringSidW: bind(advapi32, 'ConvertSidToStringSidW', 'int', [PVOID, PPVOID]),
    convertStringSidToSidW: bind(advapi32, 'ConvertStringSidToSidW', 'int', ['str16', PPVOID]),
    lookupAccountSidW: bind(advapi32, 'LookupAccountSidW', 'int', [
      'str16',
      PVOID,
      PVOID,
      koffi.pointer('uint32'),
      PVOID,
      koffi.pointer('uint32'),
      koffi.pointer('int32'),
    ]),
    localFree: bind(kernel32, 'LocalFree', PVOID, [PVOID]),
    saferCreateLevel: bind(advapi32, 'SaferCreateLevel', 'int', ['uint32', 'uint32', 'uint32', PPVOID, PVOID]),
    saferComputeTokenFromLevel: bind(advapi32, 'SaferComputeTokenFromLevel', 'int', [
      HANDLE,
      HANDLE,
      PPVOID,
      'uint32',
      PVOID,
    ]),
    saferCloseLevel: bind(advapi32, 'SaferCloseLevel', 'int', [HANDLE]),
    wtsQueryUserToken: bind(wtsapi32, 'WTSQueryUserToken', 'int', ['uint32', PPVOID]),
    wtsGetActiveConsoleSessionId: bind(kernel32, 'WTSGetActiveConsoleSessionId', 'uint32', []),
  }
  cached = api
  return api
}

function win32Error(api, name, code, detail) {
  const buffer = Buffer.alloc(1024)
  let text = ''
  try {
    const length = api.formatMessageW(0x1000, null, code, 0, buffer, buffer.length / 2, null)
    if (length > 0) text = buffer.subarray(0, length * 2).toString('utf16le').trim()
  } catch {}
  const error = new Error(`exec-privilege: ${name} failed (${code}${text ? `: ${text}` : ''})${detail ? ` — ${detail}` : ''}`)
  error.code = code
  error.win32Name = name
  return error
}

function lastError(api, name, detail) {
  return win32Error(api, name, api.getLastError(), detail)
}

function openProcessTokenForPid(api, pid, access) {
  const processHandle = api.openProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
  if (!processHandle) throw lastError(api, 'OpenProcess', `pid ${pid}`)
  try {
    const slot = api.koffi.alloc(api.PVOID, 1)
    try {
      if (!api.openProcessToken(processHandle, access, slot)) throw lastError(api, 'OpenProcessToken', `pid ${pid}`)
      const token = api.koffi.decode(slot, api.HANDLE)
      if (!token) throw win32Error(api, 'OpenProcessToken', api.getLastError(), 'null token')
      return token
    } finally {
      api.koffi.free(slot)
    }
  } finally {
    api.closeHandle(processHandle)
  }
}

function openCurrentToken(api, access) {
  const slot = api.koffi.alloc(api.PVOID, 1)
  try {
    if (!api.openProcessToken(api.getCurrentProcess(), access, slot)) throw lastError(api, 'OpenProcessToken', 'current process')
    const token = api.koffi.decode(slot, api.HANDLE)
    if (!token) throw win32Error(api, 'OpenProcessToken', api.getLastError(), 'null token')
    return token
  } finally {
    api.koffi.free(slot)
  }
}

function tokenInfoBuffer(api, token, infoClass, size) {
  const buffer = Buffer.alloc(size)
  const neededSlot = api.koffi.alloc('uint32', 1)
  try {
    const ok = api.getTokenInformation(token, infoClass, buffer, buffer.length, neededSlot)
    const needed = api.koffi.decode(neededSlot, 'uint32')
    if (!ok) {
      if (needed > buffer.length) return tokenInfoBuffer(api, token, infoClass, needed)
      throw lastError(api, 'GetTokenInformation', `class ${infoClass}`)
    }
    return needed > 0 ? buffer.subarray(0, needed) : buffer
  } finally {
    api.koffi.free(neededSlot)
  }
}

function sidToString(api, sidPtr) {
  if (!sidPtr) return undefined
  const slot = api.koffi.alloc(api.PPVOID, 1)
  try {
    if (!api.convertSidToStringSidW(sidPtr, slot)) throw lastError(api, 'ConvertSidToStringSidW')
    const stringPtr = api.koffi.decode(slot, api.PVOID)
    if (!stringPtr) return undefined
    try {
      // koffi's str16 decoder does not accept a raw external pointer on every
      // build; read a bounded UTF-16 window and stop at the terminator.
      const units = api.koffi.decode(stringPtr, 'uint16', 128)
      let text = ''
      for (const unit of units) {
        if (unit === 0) break
        text += String.fromCharCode(unit)
      }
      return text
    } finally {
      api.localFree(stringPtr)
    }
  } finally {
    api.koffi.free(slot)
  }
}

function sidAndAttributes(api, buffer, offset = 0) {
  const sidPtr = api.koffi.decode(buffer, offset, api.PVOID)
  const attributes = buffer.readUInt32LE(offset + 8)
  return { sidPtr, attributes }
}

function lookupSidName(api, sidPtr) {
  if (!sidPtr) return undefined
  const name = Buffer.alloc(256 * 2)
  const domain = Buffer.alloc(256 * 2)
  const nameLen = api.koffi.alloc('uint32', 1)
  const domainLen = api.koffi.alloc('uint32', 1)
  const sidType = api.koffi.alloc('int32', 1)
  try {
    api.koffi.encode(nameLen, 'uint32', 256)
    api.koffi.encode(domainLen, 'uint32', 256)
    if (!api.lookupAccountSidW(null, sidPtr, name, nameLen, domain, domainLen, sidType)) return undefined
    const domainText = nameLen > 0 ? domain.subarray(0, api.koffi.decode(domainLen, 'uint32') * 2).toString('utf16le') : ''
    const nameText = name.subarray(0, api.koffi.decode(nameLen, 'uint32') * 2).toString('utf16le')
    return domainText ? `${domainText}\\${nameText}` : nameText
  } finally {
    api.koffi.free(nameLen)
    api.koffi.free(domainLen)
    api.koffi.free(sidType)
  }
}

function integrityName(sid) {
  switch (sid) {
    case SID_INTEGRITY_LOW:
      return 'Low'
    case SID_INTEGRITY_MEDIUM:
      return 'Medium'
    case SID_INTEGRITY_HIGH:
      return 'High'
    case SID_INTEGRITY_SYSTEM:
      return 'System'
    case SID_INTEGRITY_PROTECTED:
      return 'Protected'
    default:
      return sid ? `Other(${sid})` : 'Unknown'
  }
}

function readDword(api, token, infoClass) {
  const buffer = tokenInfoBuffer(api, token, infoClass, 4)
  return buffer.readUInt32LE(0)
}

/**
 * Inspect a process token (current process by default).
 * @param {string} runtimeDir DSH runtime directory.
 * @param {number} [pid] target process id; omit for the current process.
 * @returns {{userSid, userName, integritySid, integrity, elevationType, elevated, sessionId, groups, isAdmin, isSystem, isTrustedInstaller, pid}}
 */
function inspectToken(runtimeDir, pid) {
  const api = bindings(runtimeDir)
  const token = pid === undefined ? openCurrentToken(api, TOKEN_ALL_ACCESS) : openProcessTokenForPid(api, pid, TOKEN_ALL_ACCESS)
  try {
    const userBuffer = tokenInfoBuffer(api, token, 1, 256)
    const user = sidAndAttributes(api, userBuffer)
    const userSid = sidToString(api, user.sidPtr)
    const userName = lookupSidName(api, user.sidPtr)
    const integrityBuffer = tokenInfoBuffer(api, token, 25, 256)
    const integrity = sidAndAttributes(api, integrityBuffer)
    const integritySid = sidToString(api, integrity.sidPtr)
    const groupsBuffer = tokenInfoBuffer(api, token, 2, 4096)
    const count = groupsBuffer.readUInt32LE(0)
    const groups = []
    for (let index = 0; index < count; index += 1) {
      const entry = sidAndAttributes(api, groupsBuffer, 8 + index * 16)
      groups.push({
        sid: sidToString(api, entry.sidPtr),
        enabled: (entry.attributes & 0x00000004) !== 0,
        denyOnly: (entry.attributes & 0x00000010) !== 0,
        mandatory: (entry.attributes & 0x00000001) !== 0,
        owner: (entry.attributes & 0x00000008) !== 0,
      })
    }
    const bySid = (sid) => groups.find((group) => group.sid === sid)
    const admin = bySid(SID_ADMINISTRATORS)
    const trustedInstaller = bySid(SID_TRUSTED_INSTALLER)
    return {
      pid: pid ?? process.pid,
      userSid,
      userName: userName ?? userSid,
      integritySid,
      integrity: integrityName(integritySid),
      elevationType: readDword(api, token, 18),
      elevated: readDword(api, token, 20) === 1,
      sessionId: readDword(api, token, 12),
      groups,
      isAdmin: Boolean(admin && admin.enabled && !admin.denyOnly),
      isAdminMember: Boolean(admin),
      isSystem: userSid === SID_SYSTEM,
      isTrustedInstaller: Boolean(trustedInstaller && trustedInstaller.enabled),
    }
  } finally {
    api.closeHandle(token)
  }
}

function enablePrivilege(api, token, name) {
  const luid = api.koffi.alloc(api.LUID, 1)
  const privileges = api.koffi.alloc(api.TOKEN_PRIVILEGES, 1)
  try {
    if (!api.lookupPrivilegeValueW(null, name, luid)) throw lastError(api, 'LookupPrivilegeValueW', name)
    const value = api.koffi.decode(luid, api.LUID)
    api.koffi.encode(privileges, api.TOKEN_PRIVILEGES, {
      PrivilegeCount: 1,
      Privileges: [{ Luid: value, Attributes: SE_PRIVILEGE_ENABLED }],
    })
    const ok = api.adjustTokenPrivileges(token, 0, privileges, 0, null, null)
    const code = api.getLastError()
    if (!ok) throw win32Error(api, 'AdjustTokenPrivileges', code, name)
    return code !== ERROR_NOT_ALL_ASSIGNED
  } finally {
    api.koffi.free(privileges)
    api.koffi.free(luid)
  }
}

function enableCurrentProcessPrivilege(runtimeDir, name) {
  const api = bindings(runtimeDir)
  const token = openCurrentToken(api, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)
  try {
    return enablePrivilege(api, token, name)
  } finally {
    api.closeHandle(token)
  }
}

function setTokenIntegrity(api, token, sidText) {
  const sidSlot = api.koffi.alloc(api.PPVOID, 1)
  try {
    if (!api.convertStringSidToSidW(sidText, sidSlot)) throw lastError(api, 'ConvertStringSidToSidW', sidText)
    const sidPtr = api.koffi.decode(sidSlot, api.PVOID)
    if (!sidPtr) throw win32Error(api, 'ConvertStringSidToSidW', api.getLastError(), sidText)
    try {
      // TOKEN_MANDATORY_LABEL = SID_AND_ATTRIBUTES + SID bytes. A fixed 16-byte
      // prefix with the pointer written first is what SetTokenInformation expects.
      const info = Buffer.alloc(16 + 32)
      info.writeBigUInt64LE(BigInt(api.koffi.address(sidPtr)), 0)
      info.writeUInt32LE(0x20, 8) // SE_GROUP_INTEGRITY
      // The SID itself is referenced by pointer; length covers the prefix plus
      // GetLengthSid, but Windows accepts the pointer form with 16 + 32.
      if (!api.setTokenInformation(token, 25, info, info.length)) throw lastError(api, 'SetTokenInformation', `TokenIntegrityLevel ${sidText}`)
    } finally {
      api.localFree(sidPtr)
    }
  } finally {
    api.koffi.free(sidSlot)
  }
}

/**
 * Create a normal-user (SAFER level 0x20000) primary token, lowered to Medium
 * integrity, from the current process token or a session user token.
 * @param {string} runtimeDir DSH runtime directory.
 * @param {{sessionId?: number}} [options]
 * @returns {{token: bigint, close: () => void, source: string}}
 */
function createNormalUserToken(runtimeDir, options = {}) {
  const api = bindings(runtimeDir)
  let sourceToken
  let sourceLabel = 'current'
  let targetToken
  let levelHandle
  try {
    if (options.sessionId !== undefined) {
      enableCurrentProcessPrivilege(runtimeDir, 'SeTcbPrivilege')
      const slot = api.koffi.alloc(api.PPVOID, 1)
      try {
        if (!api.wtsQueryUserToken(options.sessionId, slot)) throw lastError(api, 'WTSQueryUserToken', `session ${options.sessionId}`)
        sourceToken = api.koffi.decode(slot, api.PVOID)
        sourceLabel = `session-${options.sessionId}`
      } finally {
        api.koffi.free(slot)
      }
    } else {
      sourceToken = openCurrentToken(api, TOKEN_ALL_ACCESS)
    }
    const levelSlot = api.koffi.alloc(api.PPVOID, 1)
    try {
      if (!api.saferCreateLevel(1, 0x20000, 1, levelSlot, null)) throw lastError(api, 'SaferCreateLevel', 'normal user')
      levelHandle = api.koffi.decode(levelSlot, api.PVOID)
    } finally {
      api.koffi.free(levelSlot)
    }
    const tokenSlot = api.koffi.alloc(api.PPVOID, 1)
    try {
      if (!api.saferComputeTokenFromLevel(levelHandle, sourceToken, tokenSlot, 0, null)) throw lastError(api, 'SaferComputeTokenFromLevel', 'normal user')
      targetToken = api.koffi.decode(tokenSlot, api.PVOID)
    } finally {
      api.koffi.free(tokenSlot)
    }
    setTokenIntegrity(api, targetToken, SID_INTEGRITY_MEDIUM)
    const token = targetToken
    targetToken = undefined
    return {
      token,
      source: sourceLabel,
      close() {
        if (token) api.closeHandle(token)
        if (levelHandle) api.saferCloseLevel(levelHandle)
        if (sourceToken) api.closeHandle(sourceToken)
      },
    }
  } catch (error) {
    if (targetToken) api.closeHandle(targetToken)
    if (levelHandle) api.saferCloseLevel(levelHandle)
    if (sourceToken) api.closeHandle(sourceToken)
    throw error
  }
}

/**
 * Change a primary token's session id. Requires SeTcbPrivilege, which only
 * LocalSystem holds by default. The SYSTEM helper uses this to move a
 * duplicated SYSTEM/TrustedInstaller token into the interactive console
 * session — the technique NSudo uses — so the Windows ACL sandbox runner has a
 * desktop instead of failing with Win32 740 in session 0.
 * @param {string} runtimeDir - DSH runtime directory.
 * @param {bigint} token - duplicated primary token with TOKEN_ADJUST_SESSIONID.
 * @param {number} sessionId - target session id.
 */
function setTokenSessionId(runtimeDir, token, sessionId) {
  const api = bindings(runtimeDir)
  const info = Buffer.alloc(4)
  info.writeUInt32LE(sessionId >>> 0, 0)
  if (!api.setTokenInformation(token, 12, info, info.length)) {
    throw lastError(api, 'SetTokenInformation', `TokenSessionId ${sessionId}`)
  }
}

/**
 * The active interactive console session id, or the caller's own session when
 * no console session exists.
 * @param {string} runtimeDir - DSH runtime directory.
 * @returns {number} a session id.
 */
function activeConsoleSessionId(runtimeDir) {
  const api = bindings(runtimeDir)
  const id = api.wtsGetActiveConsoleSessionId()
  if (id === 0xffffffff) return process.sessionId ?? 0
  return id >>> 0
}

/**
 * Duplicate the current process token as a primary token, optionally moving it
 * into another session. The SYSTEM helper uses this to start a SYSTEM executor
 * in the interactive session.
 * @param {string} runtimeDir - DSH runtime directory.
 * @param {{sessionId?: number}} [options]
 * @returns {{token: bigint, close: () => void, sessionId: number|undefined}}
 */
function duplicateCurrentProcessToken(runtimeDir, options = {}) {
  const api = bindings(runtimeDir)
  const source = openCurrentToken(api, TOKEN_ALL_ACCESS)
  let duplicated
  try {
    const slot = api.koffi.alloc(api.PPVOID, 1)
    try {
      if (!api.duplicateTokenEx(source, MAXIMUM_ALLOWED, null, 2, 1, slot)) {
        throw lastError(api, 'DuplicateTokenEx', 'current process token')
      }
      duplicated = api.koffi.decode(slot, api.PVOID)
    } finally {
      api.koffi.free(slot)
    }
    let sessionId
    if (options.sessionId !== undefined) {
      enableCurrentProcessPrivilege(runtimeDir, 'SeTcbPrivilege')
      setTokenSessionId(runtimeDir, duplicated, options.sessionId)
      sessionId = options.sessionId
    }
    return {
      token: duplicated,
      sessionId,
      close() {
        api.closeHandle(duplicated)
        api.closeHandle(source)
      },
    }
  } catch (error) {
    if (duplicated) api.closeHandle(duplicated)
    api.closeHandle(source)
    throw error
  }
}

/**
 * Launch a process with a primary token using CreateProcessAsUserW.
 * @returns {{pid: number, terminate: () => void, wait: (timeoutMs?: number) => number|undefined, close: () => void, handle: bigint}}
 */
function launchWithToken(runtimeDir, token, commandLine, options = {}) {
  const api = bindings(runtimeDir)
  const startup = api.koffi.alloc(api.STARTUPINFOW, 1)
  const processInfo = api.koffi.alloc(api.PROCESS_INFORMATION, 1)
  let processHandle
  let threadHandle
  try {
    api.koffi.encode(startup, api.STARTUPINFOW, {
      cb: api.STARTUPINFOW.size,
      dwFlags: 1, // STARTF_USESHOWWINDOW
      wShowWindow: 0, // SW_HIDE
      lpDesktop: options.desktop ?? null,
    })
    const cwd = options.cwd ?? process.cwd()
    const flags = options.creationFlags ?? 0
    const launched = api.createProcessAsUserW(
      token,
      options.applicationName ?? null,
      commandLine,
      null,
      null,
      0,
      flags,
      null,
      cwd,
      startup,
      processInfo,
    )
    if (!launched) throw lastError(api, 'CreateProcessAsUserW', `command: ${commandLine}, cwd: ${cwd}`)
    const info = api.koffi.decode(processInfo, api.PROCESS_INFORMATION)
    processHandle = info.hProcess
    threadHandle = info.hThread
    if (!processHandle || !threadHandle) throw win32Error(api, 'CreateProcessAsUserW', api.getLastError(), 'null handles')
    return {
      pid: info.dwProcessId,
      handle: processHandle,
      terminate() {
        if (processHandle) {
          api.terminateProcess(processHandle, 1)
        }
      },
      wait(timeoutMs = 0) {
        if (!processHandle) return undefined
        const result = api.waitForSingleObject(processHandle, timeoutMs)
        if (result === 258) return undefined
        if (result === 0xffffffff) throw lastError(api, 'WaitForSingleObject')
        const codeSlot = api.koffi.alloc('uint32', 1)
        try {
          if (!api.getExitCodeProcess(processHandle, codeSlot)) throw lastError(api, 'GetExitCodeProcess')
          return api.koffi.decode(codeSlot, 'uint32')
        } finally {
          api.koffi.free(codeSlot)
        }
      },
      close() {
        if (threadHandle) api.closeHandle(threadHandle)
        if (processHandle) api.closeHandle(processHandle)
        threadHandle = undefined
        processHandle = undefined
      },
    }
  } catch (error) {
    if (threadHandle) api.closeHandle(threadHandle)
    if (processHandle) api.closeHandle(processHandle)
    throw error
  } finally {
    api.koffi.free(processInfo)
    api.koffi.free(startup)
  }
}

function launchElevatedBootstrap(runtimeDir, cmdPath) {
  const powershell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
  const script = `$ErrorActionPreference='Stop'; Start-Process -FilePath ${powershellQuote(cmdPath)} -Verb RunAs -WindowStyle Hidden`
  const child = require('node:child_process').spawn(powershell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-Command', script], {
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  return child
}

function powershellQuote(text) {
  return `'${String(text).replaceAll("'", "''")}'`
}

function uacEnabled(runtimeDir) {
  try {
    const output = execFileSync('C:\\Windows\\System32\\reg.exe', [
      'query',
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
      '/v',
      'EnableLUA',
    ], { encoding: 'utf8' })
    const match = /EnableLUA\s+REG_DWORD\s+0x([0-9a-fA-F]+)/.exec(output)
    return match ? Number.parseInt(match[1], 16) !== 0 : false
  } catch {
    return false
  }
}

function taskExists(taskName) {
  const result = spawnSync('C:\\Windows\\System32\\schtasks.exe', ['/Query', '/TN', taskName], { encoding: 'utf8', windowsHide: true })
  return result.status === 0
}

function createSystemTask(runtimeDir, taskName, cmdPath) {
  const steps = []
  const run = (args) => {
    const result = spawnSync('C:\\Windows\\System32\\schtasks.exe', args, { encoding: 'utf8', windowsHide: true })
    steps.push({ args, status: result.status, stdout: result.stdout, stderr: result.stderr })
    if (result.status !== 0) {
      const error = new Error(`exec-privilege: schtasks ${args[0]} failed (${result.status}): ${(result.stderr || result.stdout || '').trim()}`)
      error.steps = steps
      throw error
    }
  }
  run(['/Create', '/TN', taskName, '/TR', `"${cmdPath}"`, '/SC', 'ONCE', '/ST', '23:59', '/RU', 'SYSTEM', '/RL', 'HIGHEST', '/F'])
  run(['/Run', '/TN', taskName])
  return steps
}

function deleteSystemTask(taskName) {
  try {
    execFileSync('C:\\Windows\\System32\\schtasks.exe', ['/Delete', '/TN', taskName, '/F'], { stdio: 'ignore', windowsHide: true })
    return true
  } catch {
    return false
  }
}

function queryTaskPid(taskName) {
  try {
    const output = execFileSync('C:\\Windows\\System32\\schtasks.exe', ['/Query', '/TN', taskName, '/FO', 'LIST', '/V'], { encoding: 'utf8', windowsHide: true })
    const match = /Process ID:\s*(\d+)/i.exec(output)
    return match ? Number(match[1]) : undefined
  } catch {
    return undefined
  }
}

function startTrustedInstaller(runtimeDir) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      execFileSync('C:\\Windows\\System32\\sc.exe', ['start', 'TrustedInstaller'], { stdio: 'ignore', windowsHide: true })
    } catch {}
    let text = ''
    try {
      text = execFileSync('C:\\Windows\\System32\\sc.exe', ['queryex', 'TrustedInstaller'], { encoding: 'utf8', windowsHide: true })
    } catch (error) {
      text = String(error.stdout ?? '')
    }
    const state = /STATE\s*:\s*(\d+)/.exec(text)?.[1]
    const pid = Number(/PID\s*:\s*(\d+)/.exec(text)?.[1] ?? 0)
    if (pid > 0 && state === '4') return pid
    execFileSync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-Command', 'Start-Sleep -Milliseconds 500'], { stdio: 'ignore', windowsHide: true })
  }
  throw new Error('exec-privilege: TrustedInstaller service did not reach RUNNING')
}

function duplicateTrustedInstallerToken(runtimeDir) {
  const api = bindings(runtimeDir)
  const pid = startTrustedInstaller(runtimeDir)
  const processHandle = api.openProcess(PROCESS_ALL_ACCESS, 0, pid)
  if (!processHandle) throw lastError(api, 'OpenProcess', `TrustedInstaller pid ${pid}`)
  let token
  try {
    const slot = api.koffi.alloc(api.PPVOID, 1)
    try {
      const access = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT
      if (!api.openProcessToken(processHandle, access, slot)) throw lastError(api, 'OpenProcessToken', `TrustedInstaller pid ${pid}`)
      token = api.koffi.decode(slot, api.PVOID)
    } finally {
      api.koffi.free(slot)
    }
    const dupSlot = api.koffi.alloc(api.PPVOID, 1)
    try {
      if (!api.duplicateTokenEx(token, MAXIMUM_ALLOWED, null, 2, 1, dupSlot)) throw lastError(api, 'DuplicateTokenEx', 'TrustedInstaller')
      const duplicated = api.koffi.decode(dupSlot, api.PVOID)
      return {
        token: duplicated,
        close() {
          api.closeHandle(duplicated)
          api.closeHandle(token)
        },
      }
    } finally {
      api.koffi.free(dupSlot)
    }
  } catch (error) {
    if (token) api.closeHandle(token)
    throw error
  }
}

function hostLevel(runtimeDir) {
  const info = inspectToken(runtimeDir)
  if (info.isSystem) return info.isTrustedInstaller ? 'system' : 'system'
  if (info.isTrustedInstaller) return 'trustedinstaller'
  if (info.isAdmin) return 'admin'
  return 'user'
}

function configDacl(runtimeDir, configPath, level) {
  // Administrator/SYSTEM-only for elevated workers; the interactive user plus
  // SYSTEM for the medium worker. Numeric SIDs avoid localized group names.
  const grants = level === 'user'
    ? ['*S-1-5-18:(R)', '*S-1-5-32-544:(R)', '*S-1-5-32-545:(R)']
    : ['*S-1-5-18:(R)', '*S-1-5-32-544:(R)']
  try {
    execFileSync('C:\\Windows\\System32\\icacls.exe', [configPath, '/inheritance:r', '/grant:r', ...grants], { stdio: 'ignore', windowsHide: true })
    return true
  } catch {
    return false
  }
}

module.exports = {
  SID_ADMINISTRATORS,
  SID_SYSTEM,
  SID_TRUSTED_INSTALLER,
  activeConsoleSessionId,
  bindings,
  configDacl,
  createNormalUserToken,
  createSystemTask,
  deleteSystemTask,
  duplicateCurrentProcessToken,
  duplicateTrustedInstallerToken,
  enableCurrentProcessPrivilege,
  hostLevel,
  inspectToken,
  isWindows,
  launchElevatedBootstrap,
  launchWithToken,
  queryTaskPid,
  requireKoffi,
  setTokenSessionId,
  startTrustedInstaller,
  uacEnabled,
  win32Error,
}

