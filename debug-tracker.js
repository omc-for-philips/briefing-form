(() => {
  'use strict'

  const GLOBAL_NAME = 'PhilipsDebugTracker'

  if (window[GLOBAL_NAME]?.destroy) {
    window[GLOBAL_NAME].destroy()
  }

  const MAX_EVENTS = 1000
  const MAX_NETWORK = 300
  const MAX_CONSOLE = 500
  const MAX_ERRORS = 200
  const MAX_STORAGE = 300
  const LONG_TEXT_LIMIT = 180
  const JSON_SHAPE_DEPTH = 5
  const JSON_SHAPE_ITEMS = 30
  const PANEL_ID = 'philips-debug-tracker-panel'

  const originals = {
    fetch: window.fetch,
    XMLHttpRequest: window.XMLHttpRequest,
    console: {
      log: console.log,
      info: console.info,
      warn: console.warn,
      error: console.error,
      debug: console.debug,
    },
    localStorageSetItem: Storage.prototype.setItem,
    localStorageRemoveItem: Storage.prototype.removeItem,
    localStorageClear: Storage.prototype.clear,
    clipboardWriteText: navigator.clipboard?.writeText,
    createElement: document.createElement,
  }

  const state = {
    startedAt: new Date().toISOString(),
    sessionId: createId(),
    isRecording: true,
    isPatched: false,
    events: [],
    network: [],
    console: [],
    errors: [],
    storage: [],
    latest: 'Tracker started',
    counts: {
      droppedEvents: 0,
      droppedNetwork: 0,
      droppedConsole: 0,
      droppedErrors: 0,
      droppedStorage: 0,
    },
  }

  function createId() {
    return `dbg_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`
  }

  function nowIso() {
    return new Date().toISOString()
  }

  function elapsedMs(start) {
    return Math.round(performance.now() - start)
  }

  function pushLimited(list, value, max, droppedKey) {
    list.push(value)
    if (list.length > max) {
      list.shift()
      state.counts[droppedKey] += 1
    }
  }

  function markLatest(message) {
    state.latest = message
    updatePanel()
  }

  function safeUrl(value) {
    try {
      const url = new URL(String(value), window.location.href)
      const sensitiveParams = ['token', 'pat', 'key', 'secret', 'password', 'authorization', 'auth']
      sensitiveParams.forEach((name) => {
        if (url.searchParams.has(name)) url.searchParams.set(name, '[REDACTED]')
      })
      return redactText(url.toString(), 320)
    } catch {
      return redactText(String(value), 320)
    }
  }

  function redactText(value, limit = LONG_TEXT_LIMIT) {
    if (value == null) return value

    let text = String(value)
    text = text.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED]')
    text = text.replace(/(authorization["'\s:=]+)(Bearer\s+)?[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]')
    text = text.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[EMAIL_REDACTED]')
    text = text.replace(/\b\d{13,}\b/g, '[LONG_ID_REDACTED]')
    text = text.replace(/\b[A-Za-z0-9_-]{32,}\b/g, '[TOKEN_REDACTED]')

    if (text.length > limit) {
      return `${text.slice(0, limit)}... [TRUNCATED ${text.length - limit} chars]`
    }

    return text
  }

  function sanitizeKey(key) {
    return redactText(key, 80)
  }

  function isSensitiveKey(key) {
    return /authorization|cookie|token|pat|secret|password|api[-_]?key|auth/i.test(String(key))
  }

  function sanitizeHeaders(headers) {
    const output = {}

    try {
      const source = headers instanceof Headers ? Array.from(headers.entries()) : Object.entries(headers || {})
      source.forEach(([key, value]) => {
        output[sanitizeKey(key)] = isSensitiveKey(key) ? '[REDACTED]' : redactText(value, 180)
      })
    } catch (error) {
      output.error = `Unable to read headers: ${redactText(error.message)}`
    }

    return output
  }

  function sanitizeObject(value, depth = 0) {
    if (value == null) return value
    if (depth > 4) return '[MAX_DEPTH]'

    if (typeof value === 'string') return redactText(value)
    if (typeof value === 'number' || typeof value === 'boolean') return value
    if (typeof value === 'bigint') return value.toString()
    if (typeof value === 'function') return `[Function ${value.name || 'anonymous'}]`
    if (value instanceof Error) {
      return {
        name: value.name,
        message: redactText(value.message),
        stack: redactText(value.stack, 1000),
      }
    }
    if (value instanceof File) return sanitizeFile(value)
    if (value instanceof Blob) return { type: value.type || 'unknown', size: value.size, blob: true }
    if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitizeObject(item, depth + 1))

    const output = {}
    Object.entries(value).slice(0, 80).forEach(([key, item]) => {
      output[sanitizeKey(key)] = isSensitiveKey(key) ? '[REDACTED]' : sanitizeObject(item, depth + 1)
    })
    return output
  }

  function summarizeScalar(value) {
    if (value == null) return value

    if (typeof value === 'string') {
      return {
        type: 'string',
        length: value.length,
        redacted: true,
      }
    }

    if (typeof value === 'number') return { type: 'number', redacted: true }
    if (typeof value === 'boolean') return { type: 'boolean', value }
    if (typeof value === 'bigint') return { type: 'bigint', redacted: true }

    return { type: typeof value, redacted: true }
  }

  function summarizeJsonShape(value, depth = 0) {
    if (value == null || typeof value !== 'object') return summarizeScalar(value)
    if (depth >= JSON_SHAPE_DEPTH) return '[MAX_DEPTH]'

    if (Array.isArray(value)) {
      return {
        type: 'array',
        length: value.length,
        items: value.slice(0, JSON_SHAPE_ITEMS).map((item) => summarizeJsonShape(item, depth + 1)),
        truncated: value.length > JSON_SHAPE_ITEMS,
      }
    }

    const entries = Object.entries(value)
    const output = {
      type: 'object',
      keys: entries.map(([key]) => sanitizeKey(key)).slice(0, JSON_SHAPE_ITEMS),
      values: {},
      truncated: entries.length > JSON_SHAPE_ITEMS,
    }

    entries.slice(0, JSON_SHAPE_ITEMS).forEach(([key, item]) => {
      output.values[sanitizeKey(key)] = isSensitiveKey(key) ? '[REDACTED]' : summarizeJsonShape(item, depth + 1)
    })

    return output
  }

  function summarizeJsonText(text) {
    try {
      return {
        kind: 'json',
        length: text.length,
        shape: summarizeJsonShape(JSON.parse(text)),
      }
    } catch {
      return null
    }
  }

  function summarizeTextBody(text, contentType = '') {
    if (/json/i.test(contentType) || looksLikeJson(text)) {
      const jsonSummary = summarizeJsonText(text)
      if (jsonSummary) return jsonSummary
    }

    return {
      kind: 'text',
      length: text.length,
      redacted: true,
    }
  }

  function looksLikeJson(text) {
    const trimmed = String(text || '').trim()
    return (trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))
  }

  function sanitizeFile(file) {
    return {
      file: true,
      name: redactText(file.name, 140),
      size: file.size,
      type: file.type || 'unknown',
      lastModified: file.lastModified || null,
    }
  }

  function summarizeBody(body) {
    if (body == null) return null

    if (typeof body === 'string') {
      return summarizeTextBody(body)
    }

    if (body instanceof URLSearchParams) {
      const params = {}
      body.forEach((value, key) => {
        params[sanitizeKey(key)] = isSensitiveKey(key) ? '[REDACTED]' : summarizeScalar(value)
      })
      return { kind: 'URLSearchParams', fields: params }
    }

    if (body instanceof FormData) {
      const fields = []
      body.forEach((value, key) => {
        fields.push({
          name: sanitizeKey(key),
          value: value instanceof File ? sanitizeFile(value) : summarizeScalar(value),
        })
      })
      return { kind: 'FormData', fields }
    }

    if (body instanceof Blob) {
      return { kind: 'Blob', size: body.size, type: body.type || 'unknown' }
    }

    if (body instanceof ArrayBuffer) {
      return { kind: 'ArrayBuffer', bytes: body.byteLength }
    }

    if (ArrayBuffer.isView(body)) {
      return { kind: body.constructor.name, bytes: body.byteLength }
    }

    if (body instanceof ReadableStream) {
      return { kind: 'ReadableStream', preview: '[not captured]' }
    }

    return { kind: body.constructor?.name || typeof body, shape: summarizeJsonShape(body) }
  }

  function contentLooksBinary(contentType) {
    return /octet-stream|image\/|audio\/|video\/|font\/|zip|pdf|spreadsheet|excel|multipart/i.test(contentType || '')
  }

  async function summarizeResponse(response) {
    const contentType = response.headers?.get?.('content-type') || ''
    const summary = {
      contentType,
      skipped: false,
    }

    if (contentLooksBinary(contentType)) {
      summary.skipped = true
      summary.body = '[binary response skipped]'
      return summary
    }

    try {
      const clone = response.clone()
      const text = await clone.text()
      summary.body = summarizeTextBody(text, contentType)
      summary.length = text.length
    } catch (error) {
      summary.body = `Unable to read response summary: ${redactText(error.message)}`
    }

    return summary
  }

  function summarizeResponseAsync(response, entry) {
    summarizeResponse(response)
      .then((responseSummary) => {
        entry.response = responseSummary
        updatePanel()
      })
      .catch((error) => {
        entry.response = {
          contentType: response.headers?.get?.('content-type') || '',
          skipped: true,
          body: `Unable to read response summary: ${redactText(error.message)}`,
        }
        updatePanel()
      })
  }

  function getRequestInfo(input, init = {}) {
    const request = input instanceof Request ? input : null
    return {
      method: init.method || request?.method || 'GET',
      url: safeUrl(request?.url || input),
      requestHeaders: sanitizeHeaders({
        ...(request ? Object.fromEntries(request.headers.entries()) : {}),
        ...(init.headers ? Object.fromEntries(new Headers(init.headers).entries()) : {}),
      }),
      requestBody: summarizeBody(init.body),
    }
  }

  function recordEvent(type, detail = {}) {
    if (!state.isRecording) return

    pushLimited(state.events, {
      id: createId(),
      at: nowIso(),
      type,
      url: safeUrl(window.location.href),
      detail: sanitizeObject(detail),
    }, MAX_EVENTS, 'droppedEvents')

    markLatest(`${type}: ${detail.summary || detail.label || detail.selector || ''}`.trim())
  }

  function recordNetwork(entry) {
    if (!state.isRecording) return

    const storedEntry = {
      id: createId(),
      at: nowIso(),
      ...sanitizeObject(entry),
    }

    pushLimited(state.network, storedEntry, MAX_NETWORK, 'droppedNetwork')

    markLatest(`network: ${entry.method || 'GET'} ${entry.status || entry.error || ''}`)
    return storedEntry
  }

  function recordConsole(level, args) {
    if (!state.isRecording) return

    pushLimited(state.console, {
      id: createId(),
      at: nowIso(),
      level,
      args: Array.from(args).map((arg) => sanitizeObject(arg)),
    }, MAX_CONSOLE, 'droppedConsole')

    if (level === 'error' || level === 'warn') markLatest(`console.${level}`)
  }

  function recordError(type, error) {
    if (!state.isRecording) return

    pushLimited(state.errors, {
      id: createId(),
      at: nowIso(),
      type,
      error: sanitizeObject(error),
      url: safeUrl(window.location.href),
    }, MAX_ERRORS, 'droppedErrors')

    markLatest(`${type}: ${error?.message || error?.reason || 'error'}`)
  }

  function recordStorage(action, storageArea, key, value) {
    if (!state.isRecording) return

    pushLimited(state.storage, {
      id: createId(),
      at: nowIso(),
      action,
      storageArea,
      key: sanitizeKey(key || ''),
      value: isSensitiveKey(key) ? '[REDACTED]' : summarizeStorageValue(value),
    }, MAX_STORAGE, 'droppedStorage')

    markLatest(`storage.${action}: ${key || storageArea}`)
  }

  function summarizeStorageValue(value) {
    if (value == null) return value
    const text = String(value)
    return summarizeTextBody(text)
  }

  function elementSummary(target) {
    if (!target || target === window || target === document) return { selector: String(target) }

    const element = target.closest?.('button, a, input, select, textarea, [role], [data-testid], [id], [class]') || target
    const tag = element.tagName?.toLowerCase?.() || 'unknown'
    const id = element.id ? `#${element.id}` : ''
    const classes = typeof element.className === 'string'
      ? element.className.split(/\s+/).filter(Boolean).slice(0, 4).map((item) => `.${item}`).join('')
      : ''
    const label = getElementLabel(element)
    const value = getElementValue(element)

    return {
      selector: `${tag}${id}${classes}`,
      tag,
      role: element.getAttribute?.('role') || null,
      type: element.getAttribute?.('type') || null,
      name: redactText(element.getAttribute?.('name') || '', 80),
      label,
      value,
    }
  }

  function getElementLabel(element) {
    const aria = element.getAttribute?.('aria-label')
    if (aria) return redactText(aria, 120)

    const labelledBy = element.getAttribute?.('aria-labelledby')
    if (labelledBy) {
      const label = document.getElementById(labelledBy)
      if (label?.textContent) return redactText(label.textContent.trim(), 120)
    }

    if (element.id) {
      const label = document.querySelector(`label[for="${CSS.escape(element.id)}"]`)
      if (label?.textContent) return redactText(label.textContent.trim(), 120)
    }

    const text = element.textContent?.trim?.()
    return text ? redactText(text.replace(/\s+/g, ' '), 120) : null
  }

  function getElementValue(element) {
    if (!('value' in element)) return null

    if (element.type === 'password') return '[REDACTED]'
    if (element.type === 'file') {
      return Array.from(element.files || []).map((file) => sanitizeFile(file))
    }

    const rawValue = element.value
    if (rawValue == null || rawValue === '') return rawValue

    return summarizeScalar(rawValue)
  }

  function patchFetch() {
    window.fetch = async function trackedFetch(input, init = {}) {
      const started = performance.now()
      const info = getRequestInfo(input, init)

      try {
        const response = await originals.fetch.apply(this, arguments)
        const storedEntry = recordNetwork({
          kind: 'fetch',
          ...info,
          status: response.status,
          ok: response.ok,
          durationMs: elapsedMs(started),
          responseHeaders: sanitizeHeaders(response.headers),
          response: {
            contentType: response.headers?.get?.('content-type') || '',
            pending: true,
          },
        })
        if (storedEntry) summarizeResponseAsync(response, storedEntry)
        return response
      } catch (error) {
        recordNetwork({
          kind: 'fetch',
          ...info,
          durationMs: elapsedMs(started),
          error: sanitizeObject(error),
        })
        throw error
      }
    }
  }

  function patchXhr() {
    function TrackedXMLHttpRequest() {
      const xhr = new originals.XMLHttpRequest()
      const meta = {
        method: 'GET',
        url: '',
        requestHeaders: {},
        requestBody: null,
        started: 0,
      }

      const originalOpen = xhr.open
      const originalSend = xhr.send
      const originalSetRequestHeader = xhr.setRequestHeader

      xhr.open = function open(method, url) {
        meta.method = method || 'GET'
        meta.url = safeUrl(url)
        return originalOpen.apply(xhr, arguments)
      }

      xhr.setRequestHeader = function setRequestHeader(name, value) {
        meta.requestHeaders[sanitizeKey(name)] = isSensitiveKey(name) ? '[REDACTED]' : redactText(value)
        return originalSetRequestHeader.apply(xhr, arguments)
      }

      xhr.send = function send(body) {
        meta.started = performance.now()
        meta.requestBody = summarizeBody(body)

        xhr.addEventListener('loadend', () => {
          const contentType = xhr.getResponseHeader('content-type') || ''
          recordNetwork({
            kind: 'xhr',
            method: meta.method,
            url: meta.url,
            requestHeaders: meta.requestHeaders,
            requestBody: meta.requestBody,
            status: xhr.status,
            ok: xhr.status >= 200 && xhr.status < 300,
            durationMs: elapsedMs(meta.started),
            response: {
              contentType,
              body: getXhrResponsePreview(xhr, contentType),
              skipped: contentLooksBinary(contentType),
            },
          })
        })

        return originalSend.apply(xhr, arguments)
      }

      return xhr
    }

    TrackedXMLHttpRequest.prototype = originals.XMLHttpRequest.prototype
    window.XMLHttpRequest = TrackedXMLHttpRequest
  }

  function patchConsole() {
    Object.keys(originals.console).forEach((level) => {
      console[level] = function trackedConsole() {
        recordConsole(level, arguments)
        return originals.console[level].apply(console, arguments)
      }
    })
  }

  function patchStorage() {
    Storage.prototype.setItem = function trackedSetItem(key, value) {
      recordStorage('setItem', storageName(this), key, value)
      return originals.localStorageSetItem.apply(this, arguments)
    }

    Storage.prototype.removeItem = function trackedRemoveItem(key) {
      recordStorage('removeItem', storageName(this), key, null)
      return originals.localStorageRemoveItem.apply(this, arguments)
    }

    Storage.prototype.clear = function trackedClear() {
      recordStorage('clear', storageName(this), '', null)
      return originals.localStorageClear.apply(this, arguments)
    }
  }

  function storageName(storage) {
    if (storage === window.localStorage) return 'localStorage'
    if (storage === window.sessionStorage) return 'sessionStorage'
    return 'Storage'
  }

  function patchClipboardAndDownload() {
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText = function trackedWriteText(text) {
        recordEvent('clipboard.writeText', {
          summary: 'clipboard write',
          value: summarizeStorageValue(text),
        })
        return originals.clipboardWriteText.apply(this, arguments)
      }
    }

    document.createElement = function trackedCreateElement(tagName) {
      const element = originals.createElement.apply(document, arguments)

      if (String(tagName).toLowerCase() === 'a') {
        const originalClick = element.click
        element.click = function trackedAnchorClick() {
          if (element.download || String(element.href || '').startsWith('blob:')) {
            recordEvent('download', {
              summary: 'anchor download',
              download: redactText(element.download || '', 160),
              href: safeUrl(element.href || ''),
            })
          }
          return originalClick.apply(element, arguments)
        }
      }

      return element
    }
  }

  function addListeners() {
    document.addEventListener('click', onClick, true)
    document.addEventListener('submit', onSubmit, true)
    document.addEventListener('change', onChange, true)
    document.addEventListener('input', onInput, true)
    document.addEventListener('keydown', onKeydown, true)
    window.addEventListener('hashchange', onHashChange, true)
    document.addEventListener('visibilitychange', onVisibilityChange, true)
    window.addEventListener('error', onWindowError, true)
    window.addEventListener('unhandledrejection', onUnhandledRejection, true)
  }

  function removeListeners() {
    document.removeEventListener('click', onClick, true)
    document.removeEventListener('submit', onSubmit, true)
    document.removeEventListener('change', onChange, true)
    document.removeEventListener('input', onInput, true)
    document.removeEventListener('keydown', onKeydown, true)
    window.removeEventListener('hashchange', onHashChange, true)
    document.removeEventListener('visibilitychange', onVisibilityChange, true)
    window.removeEventListener('error', onWindowError, true)
    window.removeEventListener('unhandledrejection', onUnhandledRejection, true)
  }

  function onClick(event) {
    if (panelContains(event.target)) return
    recordEvent('click', elementSummary(event.target))
  }

  function onSubmit(event) {
    recordEvent('submit', elementSummary(event.target))
  }

  function onChange(event) {
    recordEvent('change', elementSummary(event.target))
  }

  function onInput(event) {
    const target = event.target
    if (!target || target.type === 'password') return

    recordEvent('input', {
      ...elementSummary(target),
      value: 'value' in target ? {
        length: String(target.value || '').length,
        preview: target.value?.length > 0 ? '[input captured redacted]' : '',
      } : null,
    })
  }

  function onKeydown(event) {
    if (panelContains(event.target)) return
    if (!event.metaKey && !event.ctrlKey && !event.altKey && !['Enter', 'Escape', 'Tab'].includes(event.key)) return

    recordEvent('keydown', {
      summary: event.key,
      key: event.key,
      ctrlKey: event.ctrlKey,
      metaKey: event.metaKey,
      altKey: event.altKey,
      shiftKey: event.shiftKey,
      target: elementSummary(event.target),
    })
  }

  function onHashChange(event) {
    recordEvent('hashchange', {
      oldURL: safeUrl(event.oldURL),
      newURL: safeUrl(event.newURL),
    })
  }

  function onVisibilityChange() {
    recordEvent('visibilitychange', { state: document.visibilityState })
  }

  function onWindowError(event) {
    recordError('window.error', {
      message: event.message,
      filename: event.filename,
      lineno: event.lineno,
      colno: event.colno,
      error: event.error,
    })
  }

  function onUnhandledRejection(event) {
    recordError('unhandledrejection', event.reason)
  }

  function getXhrResponsePreview(xhr, contentType) {
    if (contentLooksBinary(contentType)) return '[binary response skipped]'
    if (xhr.responseType && xhr.responseType !== 'text' && xhr.responseType !== '') {
      return `[${xhr.responseType} response skipped]`
    }

    try {
      return summarizeTextBody(xhr.responseText || '', contentType)
    } catch (error) {
      return `Unable to read XHR response summary: ${redactText(error.message)}`
    }
  }

  function panelContains(target) {
    return document.getElementById(PANEL_ID)?.contains(target)
  }

  function patchAll() {
    if (state.isPatched) return

    patchFetch()
    patchXhr()
    patchConsole()
    patchStorage()
    patchClipboardAndDownload()
    addListeners()
    state.isPatched = true
  }

  function restoreAll() {
    if (!state.isPatched) return

    window.fetch = originals.fetch
    window.XMLHttpRequest = originals.XMLHttpRequest
    Object.keys(originals.console).forEach((level) => {
      console[level] = originals.console[level]
    })
    Storage.prototype.setItem = originals.localStorageSetItem
    Storage.prototype.removeItem = originals.localStorageRemoveItem
    Storage.prototype.clear = originals.localStorageClear
    if (navigator.clipboard?.writeText && originals.clipboardWriteText) {
      navigator.clipboard.writeText = originals.clipboardWriteText
    }
    document.createElement = originals.createElement
    removeListeners()
    state.isPatched = false
  }

  function getMeta() {
    return {
      app: 'Philips Briefing Form',
      tracker: GLOBAL_NAME,
      sessionId: state.sessionId,
      startedAt: state.startedAt,
      exportedAt: nowIso(),
      recording: state.isRecording,
      location: safeUrl(window.location.href),
      hash: redactText(window.location.hash, 260),
      userAgent: navigator.userAgent,
      language: navigator.language,
      viewport: {
        width: window.innerWidth,
        height: window.innerHeight,
        devicePixelRatio: window.devicePixelRatio,
      },
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    }
  }

  function getReport() {
    return {
      meta: getMeta(),
      summary: {
        events: state.events.length,
        network: state.network.length,
        console: state.console.length,
        errors: state.errors.length,
        storage: state.storage.length,
        dropped: { ...state.counts },
        latest: state.latest,
      },
      events: state.events,
      network: state.network,
      console: state.console,
      errors: state.errors,
      storage: state.storage,
    }
  }

  async function copyReport() {
    const json = JSON.stringify(getReport(), null, 2)
    if (!navigator.clipboard?.writeText) {
      throw new Error('Clipboard API is not available in this browser context.')
    }
    await navigator.clipboard.writeText(json)
    markLatest('report copied')
    return json
  }

  function downloadReport() {
    const json = JSON.stringify(getReport(), null, 2)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = originals.createElement.call(document, 'a')
    anchor.href = url
    anchor.download = `philips-debug-report-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
    markLatest('report downloaded')
    return json
  }

  function start() {
    state.isRecording = true
    patchAll()
    markLatest('recording started')
    return getReport()
  }

  function stop() {
    state.isRecording = false
    restoreAll()
    markLatest('recording stopped')
    return getReport()
  }

  function reset() {
    state.events = []
    state.network = []
    state.console = []
    state.errors = []
    state.storage = []
    state.startedAt = nowIso()
    state.sessionId = createId()
    state.latest = 'report reset'
    state.counts = {
      droppedEvents: 0,
      droppedNetwork: 0,
      droppedConsole: 0,
      droppedErrors: 0,
      droppedStorage: 0,
    }
    updatePanel()
    return getReport()
  }

  function destroy() {
    restoreAll()
    document.getElementById(PANEL_ID)?.remove()
    delete window[GLOBAL_NAME]
  }

  function injectPanel() {
    document.getElementById(PANEL_ID)?.remove()

    const panel = originals.createElement.call(document, 'div')
    panel.id = PANEL_ID
    panel.innerHTML = `
      <style>
        #${PANEL_ID} {
          position: fixed;
          right: 16px;
          bottom: 16px;
          z-index: 2147483647;
          width: 280px;
          padding: 12px;
          border: 1px solid #cbd5e1;
          border-radius: 10px;
          background: #ffffff;
          color: #0f172a;
          box-shadow: 0 18px 60px rgba(15, 23, 42, 0.25);
          font: 12px/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        #${PANEL_ID} * { box-sizing: border-box; }
        #${PANEL_ID} .pdt-head {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 8px;
          margin-bottom: 10px;
        }
        #${PANEL_ID} .pdt-title {
          font-weight: 700;
          font-size: 13px;
        }
        #${PANEL_ID} .pdt-pill {
          border-radius: 999px;
          padding: 3px 8px;
          background: #e0f2fe;
          color: #075985;
          font-weight: 700;
          text-transform: uppercase;
          font-size: 10px;
        }
        #${PANEL_ID}.is-stopped .pdt-pill {
          background: #fee2e2;
          color: #991b1b;
        }
        #${PANEL_ID} .pdt-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 6px;
          margin-bottom: 10px;
        }
        #${PANEL_ID} .pdt-stat {
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          padding: 6px;
          background: #f8fafc;
        }
        #${PANEL_ID} .pdt-stat strong {
          display: block;
          font-size: 15px;
        }
        #${PANEL_ID} .pdt-latest {
          min-height: 32px;
          max-height: 48px;
          overflow: hidden;
          margin-bottom: 10px;
          color: #475569;
          word-break: break-word;
        }
        #${PANEL_ID} .pdt-actions {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 6px;
        }
        #${PANEL_ID} button {
          appearance: none;
          border: 1px solid #cbd5e1;
          border-radius: 8px;
          background: #0b5ed7;
          color: #ffffff;
          cursor: pointer;
          font: inherit;
          font-weight: 700;
          padding: 7px 8px;
        }
        #${PANEL_ID} button.secondary {
          background: #ffffff;
          color: #0f172a;
        }
        #${PANEL_ID} button:hover {
          filter: brightness(0.96);
        }
      </style>
      <div class="pdt-head">
        <div class="pdt-title">Debug Tracker</div>
        <div class="pdt-pill" data-pdt-status>Recording</div>
      </div>
      <div class="pdt-grid">
        <div class="pdt-stat"><strong data-pdt-events>0</strong>Events</div>
        <div class="pdt-stat"><strong data-pdt-network>0</strong>Network</div>
        <div class="pdt-stat"><strong data-pdt-errors>0</strong>Errors</div>
      </div>
      <div class="pdt-latest" data-pdt-latest>Tracker started</div>
      <div class="pdt-actions">
        <button type="button" data-pdt-toggle>Stop</button>
        <button type="button" class="secondary" data-pdt-reset>Reset</button>
        <button type="button" class="secondary" data-pdt-copy>Copy JSON</button>
        <button type="button" class="secondary" data-pdt-download>Download JSON</button>
      </div>
    `

    panel.querySelector('[data-pdt-toggle]').addEventListener('click', () => {
      if (state.isRecording) stop()
      else start()
    })
    panel.querySelector('[data-pdt-reset]').addEventListener('click', reset)
    panel.querySelector('[data-pdt-copy]').addEventListener('click', () => {
      copyReport().catch((error) => {
        recordError('copyReport', error)
        originals.console.error.call(console, 'Failed to copy debug report:', error)
      })
    })
    panel.querySelector('[data-pdt-download]').addEventListener('click', downloadReport)

    document.body.appendChild(panel)
    updatePanel()
  }

  function updatePanel() {
    const panel = document.getElementById(PANEL_ID)
    if (!panel) return

    panel.classList.toggle('is-stopped', !state.isRecording)
    panel.querySelector('[data-pdt-status]').textContent = state.isRecording ? 'Recording' : 'Stopped'
    panel.querySelector('[data-pdt-toggle]').textContent = state.isRecording ? 'Stop' : 'Start'
    panel.querySelector('[data-pdt-events]').textContent = state.events.length
    panel.querySelector('[data-pdt-network]').textContent = state.network.length
    panel.querySelector('[data-pdt-errors]').textContent = state.errors.length
    panel.querySelector('[data-pdt-latest]').textContent = state.latest || ''
  }

  window[GLOBAL_NAME] = {
    start,
    stop,
    reset,
    getReport,
    copyReport,
    downloadReport,
    destroy,
  }

  patchAll()
  injectPanel()
  recordEvent('tracker.start', { summary: 'Debug tracker installed' })
  originals.console.info.call(console, `${GLOBAL_NAME} installed. Use window.${GLOBAL_NAME}.getReport() to inspect the current report.`)
})()
