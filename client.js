// @local/dsh-exec-privilege/client
//
// Composer control + menu for the process-wide execution privilege. The
// control sits immediately to the right of the permission preset selector
// (the first entry of `conversation.input.left`, before the docwrite mode).
window.__ModuleLoader__.load({
  id: '@local/dsh-exec-privilege',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const LEVEL_TEXT = {
      user: {
        descZh: '当前用户的中等完整性令牌；管理员组为拒绝状态。',
        descEn: 'The current user with a Medium-integrity token and Administrators deny-only.',
      },
      admin: {
        descZh: 'Windows 管理员（高完整性）。首次切换可能需要 UAC 授权。',
        descEn: 'A Windows administrator token (High integrity). UAC may prompt on first use.',
      },
      system: {
        descZh: 'Windows 系统账户（SYSTEM）。可访问系统级资源，风险很高。',
        descEn: 'The Windows SYSTEM account. System-wide access, high risk.',
      },
      trustedinstaller: {
        descZh: 'Windows 模块安装程序身份（SYSTEM + TrustedInstaller 服务组）。可修改系统保护目录。',
        descEn: 'The Windows Modules Installer identity (SYSTEM + TrustedInstaller group). Protected system paths become writable.',
      },
      root: {
        descZh: 'Linux/macOS 超级用户；Windows 上不可用。',
        descEn: 'The Linux/macOS superuser; unavailable on Windows.',
      },
    }

    function useLang(ctx) {
      const service = ctx.get('locale')
      const [, setRevision] = React.useState(0)
      React.useEffect(() => {
        if (!service || typeof service.subscribe !== 'function') return undefined
        return service.subscribe(() => setRevision((value) => value + 1))
      }, [service])
      let active = 'zh'
      try {
        active = service?.getLocale?.().active ?? 'zh'
      } catch {
        active = 'zh'
      }
      return active.toLowerCase().startsWith('en') ? 'en' : 'zh'
    }

    function pick(lang, zh, en) {
      return lang === 'en' ? en : zh
    }

    function levelName(level, lang) {
      if (!level) return ''
      return pick(lang, level.labelZh, level.labelEn)
    }

    function levelShort(level, lang) {
      if (!level) return ''
      return pick(lang, level.shortZh, level.shortEn)
    }

    function levelDescription(level, lang) {
      if (!level) return ''
      const fallback = LEVEL_TEXT[level.id]
      if (fallback) return pick(lang, fallback.descZh, fallback.descEn)
      return pick(lang, level.descZh, level.descEn)
    }

    function identityText(identity, lang) {
      if (!identity) return pick(lang, '未知', 'Unknown')
      const name = identity.userName ?? identity.error ?? '—'
      const integrity = identity.integrity ?? '—'
      return `${name} · ${integrity}`
    }

    function riskOf(level) {
      if (!level) return 0
      if (level.id === 'system' || level.id === 'trustedinstaller') return 2
      if (level.id === 'admin') return 1
      return 0
    }

    function toneOf(level) {
      const risk = riskOf(level)
      if (risk === 2) return { color: '#dc2626', border: 'rgba(220,38,38,.55)' }
      if (risk === 1) return { color: '#b45309', border: 'rgba(180,83,9,.55)' }
      return { color: 'inherit', border: 'var(--dsw-alias-border-l1, #ccc)' }
    }

    function ShieldIcon({ size = 14 }) {
      return h(
        'svg',
        {
          viewBox: '0 0 16 16',
          width: size,
          height: size,
          'aria-hidden': true,
          style: { display: 'block' },
        },
        h('path', {
          d: 'M8 1.4 13 3v4.6c0 3.1-2 5.6-5 7-3-1.4-5-3.9-5-7V3l5-1.6Z',
          fill: 'none',
          stroke: 'currentColor',
          strokeWidth: 1.3,
          strokeLinejoin: 'round',
        }),
        h('path', {
          d: 'm5.6 7.7 1.7 1.7 3.2-3.4',
          fill: 'none',
          stroke: 'currentColor',
          strokeWidth: 1.3,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
        }),
      )
    }

    function ChevronIcon({ open }) {
      return h(
        'svg',
        {
          viewBox: '0 0 12 12',
          width: 10,
          height: 10,
          'aria-hidden': true,
          style: {
            display: 'block',
            transform: open ? 'rotate(180deg)' : 'none',
            transition: 'transform .12s',
            opacity: 0.7,
          },
        },
        h('path', {
          d: 'm2.5 4.3 3.5 3.5 3.5-3.5',
          fill: 'none',
          stroke: 'currentColor',
          strokeWidth: 1.4,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
        }),
      )
    }

    function makeExecPrivilege(ctx) {
      return function ExecPrivilegeControl(props) {
        const lang = useLang(ctx)
        const [state, setState] = React.useState(null)
        const [open, setOpen] = React.useState(false)
        const [busy, setBusy] = React.useState(null)
        const [error, setError] = React.useState(null)
        const [acknowledged, setAcknowledged] = React.useState(false)
        const rootRef = React.useRef(null)
        const aliveRef = React.useRef(true)

        const load = React.useCallback(async () => {
          try {
            const response = await fetch('/exec-privilege/state', {
              cache: 'no-store',
              credentials: 'same-origin',
              headers: { accept: 'application/json' },
            })
            if (!response.ok) throw new Error(`HTTP ${response.status}`)
            const data = await response.json()
            if (!aliveRef.current) return
            if (data?.ok) {
              setState(data)
              if (data.lastError) setError(data.lastError)
            } else {
              setState(data?.state ?? null)
              setError(data?.error ?? '读取执行权限失败')
            }
          } catch (err) {
            if (aliveRef.current) setError(err?.message ?? String(err))
          }
        }, [])

        React.useEffect(() => {
          aliveRef.current = true
          void load()
          const timer = setInterval(() => {
            if (!aliveRef.current) return
            void load()
          }, 3000)
          const onFocus = () => void load()
          window.addEventListener('focus', onFocus)
          document.addEventListener('visibilitychange', onFocus)
          return () => {
            aliveRef.current = false
            clearInterval(timer)
            window.removeEventListener('focus', onFocus)
            document.removeEventListener('visibilitychange', onFocus)
          }
        }, [load])

        React.useEffect(() => {
          if (!open) return undefined
          const onDown = (event) => {
            if (!rootRef.current?.contains(event.target)) setOpen(false)
          }
          document.addEventListener('pointerdown', onDown)
          return () => document.removeEventListener('pointerdown', onDown)
        }, [open])

        React.useEffect(() => {
          setAcknowledged(false)
        }, [state?.pendingRequest?.id])

        const post = async (path, body) => {
          const response = await fetch(path, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json', accept: 'application/json' },
            body: JSON.stringify(body),
          })
          const data = await response.json()
          if (!data?.ok) throw new Error(data?.error ?? `HTTP ${response.status}`)
          if (data.state) setState(data.state)
          return data
        }

        const applyLevel = async (level) => {
          setBusy(level.id)
          setError(null)
          try {
            await post('/exec-privilege/level', { level: level.id })
            setOpen(false)
            return true
          } catch (err) {
            setError(err?.message ?? String(err))
            return false
          } finally {
            if (aliveRef.current) setBusy(null)
          }
        }

        // Elevated targets never apply directly: this only creates a request,
        // and the dedicated confirmation below asks the user. The model's
        // request_exec_privilege tool uses the same request object.
        const requestLevel = async (level) => {
          setBusy(level.id)
          setError(null)
          try {
            await post('/exec-privilege/request', {
              level: level.id,
              reason: pick(
                lang,
                '用户在「执行权限」菜单中选择了该等级。',
                'The user selected this level in the Execution privilege menu.',
              ),
            })
            setOpen(false)
            return true
          } catch (err) {
            setError(err?.message ?? String(err))
            return false
          } finally {
            if (aliveRef.current) setBusy(null)
          }
        }

        const decidePending = async (allow) => {
          const request = state?.pendingRequest
          if (!request) return false
          setBusy(request.level)
          setError(null)
          try {
            await post('/exec-privilege/decision', {
              requestId: request.id,
              decision: allow ? 'allow' : 'deny',
            })
            setOpen(false)
            return true
          } catch (err) {
            setError(err?.message ?? String(err))
            return false
          } finally {
            if (aliveRef.current) setBusy(null)
          }
        }

        const levels = Array.isArray(state?.levels) ? state.levels : []
        if (!state || levels.length === 0) return null

        const current = levels.find((level) => level.selected) ?? levels[0]
        const tone = toneOf(current)
        const effective = state.effective
        const busyNow = busy !== null || state.switching === true
        const needsConsent = (level) =>
          level.needsConsent === true ||
          Number(level.rank) > Number(current.rank ?? 0)

        const choose = (level) => {
          if (!level.reachable || busyNow) return
          if (level.selected && level.active) {
            setOpen(false)
            return
          }
          if (needsConsent(level)) {
            void requestLevel(level)
            return
          }
          void applyLevel(level)
        }

        const title = pick(
          lang,
          `执行权限：${levelName(current, lang)}（${identityText(effective?.identity, lang)}）`,
          `Execution privilege: ${levelName(current, lang)} (${identityText(effective?.identity, lang)})`,
        )

        const button = h(
          'button',
          {
            type: 'button',
            title,
            disabled: busyNow,
            onClick: () => {
              setOpen((value) => !value)
              void load()
            },
            style: {
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              height: 28,
              padding: '0 10px',
              borderRadius: 999,
              border: `1px solid ${tone.border}`,
              background: 'transparent',
              color: tone.color,
              fontSize: 12,
              fontWeight: 500,
              cursor: busyNow ? 'default' : 'pointer',
              whiteSpace: 'nowrap',
              opacity: busyNow ? 0.7 : 1,
            },
          },
          h(ShieldIcon, { size: 14 }),
          h('span', null, pick(lang, '执行权限', 'Exec')),
          h('strong', { style: { fontWeight: 650 } }, busyNow ? pick(lang, '切换中…', 'Switching…') : levelShort(current, lang)),
          h(ChevronIcon, { open }),
        )

        const menu = open
          ? h(
              'div',
              {
                style: {
                  position: 'absolute',
                  left: 0,
                  bottom: 'calc(100% + 8px)',
                  zIndex: 2147483000,
                  width: 380,
                  maxWidth: 'calc(100vw - 32px)',
                  maxHeight: '62vh',
                  overflow: 'auto',
                  padding: 10,
                  borderRadius: 12,
                  border: '1px solid var(--dsw-alias-border-l1, #ddd)',
                  background: 'var(--dsw-alias-bg-layer-1, #fff)',
                  color: 'var(--dsw-alias-label-primary, #111)',
                  boxShadow: '0 18px 60px rgba(0,0,0,.35)',
                  fontSize: 12,
                  lineHeight: 1.55,
                },
              },
              h(
                'div',
                { style: { padding: '2px 4px 8px' } },
                h('div', { style: { fontSize: 13, fontWeight: 700 } }, pick(lang, '执行权限', 'Execution privilege')),
                h(
                  'div',
                  { style: { color: 'var(--dsw-alias-label-secondary, #666)', marginTop: 2 } },
                  pick(
                    lang,
                    '选择 DSH 的文件修改、终端等工具以哪个 Windows 身份运行。',
                    'Choose the Windows identity used by DSH file and terminal tools.',
                  ),
                ),
              ),
              ...levels.map((level) => {
                const active = level.selected
                const risk = riskOf(level)
                const color = risk === 2 ? '#dc2626' : risk === 1 ? '#b45309' : 'inherit'
                const disabled = !level.reachable || busyNow
                const worker = level.worker
                const status = level.active
                  ? level.direct
                    ? pick(lang, '继承 DSH 本体', 'matches the DSH host')
                    : worker
                      ? `PID ${worker.pid} · ${identityText(worker.identity, lang)}`
                      : pick(lang, '正在准备…', 'preparing…')
                  : worker
                    ? `PID ${worker.pid} · ${identityText(worker.identity, lang)}`
                    : ''
                return h(
                  'button',
                  {
                    key: level.id,
                    type: 'button',
                    disabled,
                    onClick: () => choose(level),
                    style: {
                      display: 'block',
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 10px',
                      borderRadius: 8,
                      border: active
                        ? '1px solid var(--dsw-alias-border-l2, #999)'
                        : '1px solid transparent',
                      background: active ? 'rgba(127,127,127,.12)' : 'transparent',
                      color: disabled && !level.reachable ? 'var(--dsw-alias-label-dimmed, #999)' : color,
                      cursor: disabled ? 'not-allowed' : 'pointer',
                      opacity: level.reachable ? 1 : 0.65,
                    },
                  },
                  h(
                    'div',
                    { style: { display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, fontWeight: 600 } },
                    h('span', null, levelName(level, lang)),
                    active
                      ? h('span', { style: { fontSize: 11, color: 'var(--dsw-alias-state-business-primary, #2563eb)' } }, pick(lang, '✓ 当前', '✓ current'))
                      : null,
                    level.needsElevation && level.reachable
                      ? h(
                          'span',
                          {
                            style: {
                              marginLeft: 'auto',
                              fontSize: 10,
                              fontWeight: 500,
                              color: 'var(--dsw-alias-label-tertiary, #888)',
                            },
                          },
                          pick(lang, '需提升', 'elevation'),
                        )
                      : null,
                  ),
                  h(
                    'div',
                    { style: { marginTop: 2, color: 'var(--dsw-alias-label-secondary, #666)', fontSize: 11 } },
                    levelDescription(level, lang),
                  ),
                  status
                    ? h(
                        'div',
                        { style: { marginTop: 2, color: 'var(--dsw-alias-label-tertiary, #888)', fontSize: 10 } },
                        status,
                      )
                    : null,
                  !level.reachable && (level.reasonZh || level.reasonEn)
                    ? h(
                        'div',
                        { style: { marginTop: 3, color: 'var(--dsw-alias-label-tertiary, #8a6d3b)', fontSize: 10 } },
                        `⊘ ${pick(lang, level.reasonZh, level.reasonEn)}`,
                      )
                    : null,
                )
              }),
              h(
                'div',
                {
                  style: {
                    marginTop: 8,
                    padding: '8px 10px 2px',
                    borderTop: '1px solid var(--dsw-alias-border-l2, #eee)',
                    color: 'var(--dsw-alias-label-tertiary, #888)',
                    fontSize: 10,
                    lineHeight: 1.6,
                  },
                },
                h('div', null, `${pick(lang, 'DSH 本体', 'DSH host')}：${identityText(state.host?.identity, lang)}`),
                h(
                  'div',
                  null,
                  `${pick(lang, '工具执行', 'Tools')}：${effective?.ready === false ? pick(lang, '正在准备执行器…', 'preparing worker…') : identityText(effective?.identity, lang)}`,
                ),
                state.pendingRestore
                  ? h(
                      'div',
                      { style: { color: '#b45309', marginTop: 4, whiteSpace: 'pre-wrap' } },
                      pick(
                        lang,
                        `上次使用「${levelName(levels.find((entry) => entry.id === state.pendingRestore), lang) || state.pendingRestore}」，重启后需要重新确认。`,
                        `Last level was ${state.pendingRestore}; confirm it again after the restart.`,
                      ),
                    )
                  : null,
                error
                  ? h('div', { style: { color: '#dc2626', marginTop: 4, whiteSpace: 'pre-wrap' } }, error)
                  : null,
              ),
            )
          : null

        const pending = state?.pendingRequest
        const pendingLevel = pending ? levels.find((entry) => entry.id === pending.level) : null
        const pendingRisk = pendingLevel ? riskOf(pendingLevel) : 0
        const pendingModal = pending
          ? h(
              'div',
              {
                style: {
                  position: 'fixed',
                  inset: 0,
                  zIndex: 2147483600,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  padding: 24,
                  background: 'rgba(0,0,0,.55)',
                },
              },
              h(
                'div',
                {
                  style: {
                    width: 'min(540px, 100%)',
                    boxSizing: 'border-box',
                    borderRadius: 14,
                    padding: '20px 22px',
                    background: 'var(--dsw-alias-bg-layer-1, #fff)',
                    color: 'var(--dsw-alias-label-primary, #111)',
                    border: `1px solid ${pendingRisk === 2 ? 'rgba(220,38,38,.55)' : 'var(--dsw-alias-border-l2, #ccc)'}`,
                    boxShadow: '0 24px 80px rgba(0,0,0,.45)',
                    font: '13px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif',
                  },
                },
                h(
                  'div',
                  {
                    style: {
                      fontSize: 16,
                      fontWeight: 700,
                      color: pendingRisk === 2 ? '#dc2626' : 'inherit',
                    },
                  },
                  pending.source === 'model'
                    ? pick(
                        lang,
                        `模型请求提升执行权限至「${levelName(pendingLevel ?? { id: pending.level }, lang)}」`,
                        `The model requests execution privilege ${pending.level}`,
                      )
                    : pick(
                        lang,
                        `${pendingRisk === 2 ? '高风险 · ' : ''}将执行权限提升为「${levelName(pendingLevel ?? { id: pending.level }, lang)}」？`,
                        `${pendingRisk === 2 ? 'High risk · ' : ''}Elevate execution privilege to ${pending.level}?`,
                      ),
                ),
                h(
                  'div',
                  { style: { marginTop: 8, color: 'var(--dsw-alias-label-secondary, #555)' } },
                  `${pick(lang, '当前', 'current')}：${levelName(current, lang)} → ${pick(lang, '目标', 'target')}：${levelName(pendingLevel ?? { id: pending.level }, lang)}`,
                ),
                pending.reason
                  ? h(
                      'div',
                      {
                        style: {
                          marginTop: 8,
                          padding: '8px 10px',
                          borderRadius: 8,
                          background: 'rgba(127,127,127,.10)',
                          color: 'var(--dsw-alias-label-secondary, #555)',
                          whiteSpace: 'pre-wrap',
                        },
                      },
                      pending.reason,
                    )
                  : null,
                h(
                  'div',
                  { style: { marginTop: 10, color: 'var(--dsw-alias-label-secondary, #555)', whiteSpace: 'pre-wrap' } },
                  pendingLevel?.id === 'system' || pendingLevel?.id === 'trustedinstaller'
                    ? pick(
                        lang,
                        'SYSTEM/TrustedInstaller 是系统级身份：模型发起的命令和文件写入都会以该身份生效，可能修改受保护的系统文件。仅在你完全信任当前任务时继续。',
                        'SYSTEM/TrustedInstaller are system-level identities: model-initiated commands and file writes take effect with that identity and can modify protected system files. Continue only if you fully trust the current task.',
                      )
                    : pendingLevel?.id === 'admin'
                      ? pick(
                          lang,
                          '管理员身份可执行大多数系统级操作。如果当前 DSH 本体不是管理员，Windows 会弹出 UAC 授权窗口。',
                          'Administrator can perform most system-wide operations. If DSH is not already elevated, Windows will show a UAC prompt.',
                        )
                      : pick(
                          lang,
                          '普通用户使用中等完整性令牌，管理员组为拒绝状态；这是默认的安全选择。',
                          'Normal user uses a Medium-integrity token with Administrators deny-only; this is the safe default.',
                        ),
                ),
                pendingRisk === 2
                  ? h(
                      'label',
                      {
                        style: {
                          display: 'flex',
                          gap: 8,
                          alignItems: 'flex-start',
                          marginTop: 12,
                          color: '#b91c1c',
                          fontSize: 12,
                          cursor: 'pointer',
                        },
                      },
                      h('input', {
                        type: 'checkbox',
                        checked: acknowledged,
                        onChange: (event) => setAcknowledged(event.target.checked),
                        style: { marginTop: 2 },
                      }),
                      h(
                        'span',
                        null,
                        pick(
                          lang,
                          '我了解该身份会以系统级权限执行模型发起的命令和文件写入。',
                          'I understand this identity executes model-initiated commands and file writes at system level.',
                        ),
                      ),
                    )
                  : null,
                error
                  ? h('div', { style: { color: '#dc2626', marginTop: 10, whiteSpace: 'pre-wrap' } }, error)
                  : null,
                h(
                  'div',
                  { style: { display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 } },
                  h(
                    'button',
                    {
                      type: 'button',
                      disabled: busyNow,
                      onClick: () => void decidePending(false),
                      style: {
                        border: '1px solid var(--dsw-alias-border-l2, #ccc)',
                        borderRadius: 8,
                        padding: '8px 14px',
                        background: 'transparent',
                        color: 'inherit',
                        cursor: busyNow ? 'not-allowed' : 'pointer',
                        fontSize: 13,
                      },
                    },
                    pick(lang, '拒绝', 'Deny'),
                  ),
                  h(
                    'button',
                    {
                      type: 'button',
                      disabled: busyNow || (pendingRisk === 2 && !acknowledged),
                      onClick: () => void decidePending(true),
                      style: {
                        border: '1px solid #dc2626',
                        borderRadius: 8,
                        padding: '8px 14px',
                        background: pendingRisk === 2 && !acknowledged ? '#fca5a5' : '#dc2626',
                        color: '#fff',
                        fontWeight: 600,
                        cursor: busyNow || (pendingRisk === 2 && !acknowledged) ? 'not-allowed' : 'pointer',
                        fontSize: 13,
                      },
                    },
                    busyNow
                      ? pick(lang, '正在切换…', 'Switching…')
                      : pick(lang, '允许', 'Allow'),
                  ),
                ),
              ),
            )
          : null

        return h(
          'div',
          { ref: rootRef, style: { position: 'relative', display: 'inline-flex' } },
          button,
          menu,
          pendingModal,
        )
      }
    }

    function apply(ctx) {
      ctx.slots.inject('conversation.input.left', () =>
        ctx.slots.register(
          {
            name: 'conversation.input.left',
            id: 'exec-privilege',
            order: 5,
            label: '执行权限',
          },
          makeExecPrivilege(ctx),
        ),
      )
    }

    return {
      inject: ['slots', 'locale'],
      apply,
    }
  },
})
