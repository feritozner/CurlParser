'use strict';

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let saved = [], selId = null;
let hist = [], cur = -1, seq = 0, inflight = 0, view = 'pretty';   // request/response history (like Burp's back/forward)

/* ================= API ================= */
async function api(path, opt = {}) {
    const r = await fetch('/api/' + path, { ...opt, headers: { 'Content-Type': 'application/json', 'X-Curlp': '1' } });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || r.statusText);
    return d;
}
const post = (path, body) => api(path, { method: 'POST', body: JSON.stringify(body) });

let toastTimer;
function toast(msg, bad) {
    const t = $('toast');
    t.textContent = msg; t.className = 'toast show' + (bad ? ' bad' : '');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => t.className = 'toast', 3500);
}

/* ================= theme (black by default) ================= */
function setTheme(t) {
    document.documentElement.dataset.theme = t;
    try { localStorage.setItem('curlp-theme', t); } catch { /* storage unavailable: theme just is not remembered */ }
}

/* ================= syntax colouring ================= */
const JSON_RE = /"(?:\\.|[^"\\\n])*"(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
function jsonHL(s) {
    let out = '', last = 0, m;
    JSON_RE.lastIndex = 0;
    while ((m = JSON_RE.exec(s))) {
        out += esc(s.slice(last, m.index));
        const tok = m[0];
        if (m[1]) out += `<span class="j-k">${esc(tok.slice(0, tok.length - m[1].length))}</span>${esc(m[1])}`;
        else out += `<span class="${tok[0] === '"' ? 'j-s' : tok === 'null' ? 'j-n' : /^(true|false)$/.test(tok) ? 'j-b' : 'j-d'}">${esc(tok)}</span>`;
        last = m.index + tok.length;
    }
    return out + esc(s.slice(last));
}

const TAG_RE = /<!--[\s\S]*?-->|<\/?[A-Za-z][\w:.-]*(?:"[^"]*"|'[^']*'|[^'">])*>|<![A-Za-z][^>]*>|<\?[\s\S]*?\?>/g;
function xmlHL(s) {
    let out = '', last = 0, m;
    TAG_RE.lastIndex = 0;
    while ((m = TAG_RE.exec(s))) {
        out += esc(s.slice(last, m.index)); last = m.index + m[0].length;
        const t = m[0];
        if (t.startsWith('<!--')) { out += `<span class="x-c">${esc(t)}</span>`; continue; }
        const p = /^(<\/?)([^\s/>]+)([\s\S]*?)(\/?>)$/.exec(t);
        if (!p) { out += esc(t); continue; }
        const attrs = esc(p[3]).replace(/([\w:.-]+)(=)(&quot;.*?&quot;|&#39;.*?&#39;)/g, '<span class="x-a">$1</span>$2<span class="x-v">$3</span>');
        out += `<span class="x-p">${esc(p[1])}</span><span class="x-t">${esc(p[2])}</span>${attrs}<span class="x-p">${esc(p[4])}</span>`;
    }
    return out + esc(s.slice(last));
}

function formHL(s) {   // application/x-www-form-urlencoded
    return s.split('&').map(p => { const k = p.indexOf('='); return k < 0 ? esc(p) : `<span class="t-hn">${esc(p.slice(0, k))}</span><span class="t-pu">=</span><span class="j-s">${esc(p.slice(k + 1))}</span>`; }).join('<span class="t-pu">&amp;</span>');
}

// Pretty-printer that never rewrites numbers or escapes (JSON.stringify would lose big integers).
function prettyJson(s) {
    JSON.parse(s);   // throws when the text is not valid JSON
    let out = '', ind = 0, inStr = false, bs = false;
    for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (inStr) { out += c; if (bs) bs = false; else if (c === '\\') bs = true; else if (c === '"') inStr = false; continue; }
        if (/\s/.test(c)) continue;
        if (c === '"') { inStr = true; out += c; }
        else if (c === '{' || c === '[') {
            let j = i + 1; while (j < s.length && /\s/.test(s[j])) j++;
            if (s[j] === (c === '{' ? '}' : ']')) { out += c + s[j]; i = j; }
            else { ind++; out += c + '\n' + '  '.repeat(ind); }
        }
        else if (c === '}' || c === ']') { ind--; out += '\n' + '  '.repeat(ind) + c; }
        else if (c === ',') out += ',\n' + '  '.repeat(ind);
        else if (c === ':') out += ': ';
        else out += c;
    }
    return out;
}

const looksJson = s => /^\s*[\[{]/.test(s) && s.length < 1e6;
const hdrHL = (n, v) => `<span class="t-hn">${esc(n)}</span><span class="t-pu">:</span> <span class="t-hv">${esc(v)}</span>`;

function hlRequest(text) {
    const i = text.indexOf('\n\n');
    const head = i < 0 ? text : text.slice(0, i), body = i < 0 ? '' : text.slice(i);   // body keeps the blank-line newlines so both layers stay aligned
    const lines = head.split('\n'), first = lines.shift();
    const m = /^(\S+)(\s+)(\S+)(.*)$/.exec(first);
    let out = m ? `<span class="t-m">${esc(m[1])}</span>${m[2]}<span class="t-p">${esc(m[3])}</span><span class="t-v">${esc(m[4])}</span>` : esc(first);
    out += lines.map(l => { const k = l.indexOf(':'); return '\n' + (k > 0 ? `<span class="t-hn">${esc(l.slice(0, k))}</span><span class="t-pu">:</span><span class="t-hv">${esc(l.slice(k + 1))}</span>` : esc(l)); }).join('');
    const form = /^content-type:\s*application\/x-www-form-urlencoded/im.test(head);
    return out + (looksJson(body) ? jsonHL(body) : form ? formHL(body) : esc(body));
}

function syncEditor() {
    const v = $('reqText').value;
    $('reqHl').innerHTML = hlRequest(v) + '\n';
    const meth = ((/^\s*(\S+)/.exec(v) || [])[1] || '—').toUpperCase();   // live method tag in the top bar
    $('methodTag').textContent = meth;
    $('methodTag').className = 'mth m-' + meth.replace(/[^A-Z]/g, '');
}

/* ================= response rendering ================= */
const sCls = c => c >= 500 ? 's5' : c >= 400 ? 's4' : c >= 300 ? 's3' : c >= 200 ? 's2' : 's1';
const fmtSize = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';

function hexDump(b64) {
    const bin = atob(b64);
    let out = '';
    for (let o = 0; o < bin.length; o += 16) {
        const chunk = bin.slice(o, o + 16);
        let hex = '', asc = '';
        for (let i = 0; i < 16; i++) {
            if (i < chunk.length) { const c = chunk.charCodeAt(i); hex += c.toString(16).padStart(2, '0') + ' '; asc += c >= 32 && c < 127 ? esc(chunk[i]) : '.'; }
            else hex += '   ';
            if (i === 7) hex += ' ';
        }
        out += `<span class="hexoff">${o.toString(16).padStart(8, '0')}</span>  <span class="hexb">${hex}</span> <span class="hexa">${asc}</span>\n`;
    }
    return out;
}

function renderResp() {
    const box = $('respView'), meta = $('respMeta'), e = hist[cur];
    if (!e) { meta.innerHTML = ''; box.className = 'resp wrap'; box.innerHTML = '<span class="muted">Send a request to see the response. Ctrl + Enter works from anywhere.</span>'; return; }
    if (!e.resp) { meta.innerHTML = `<span class="pending">#${e.n} sending…</span>`; box.className = 'resp wrap'; box.innerHTML = '<span class="pending">Waiting for the response…</span>'; return; }
    const r = e.resp;
    if (r.error) { meta.innerHTML = `<span class="st s5">#${e.n} failed</span><span>${r.duration_ms || 0} ms</span>`; box.className = 'resp wrap'; box.innerHTML = `<span class="err">${esc(r.error)}</span>`; return; }

    meta.innerHTML = `<span class="st ${sCls(r.status_code)}">${r.status_code} ${esc(r.status_text)}</span><span>${r.duration_ms} ms</span><span>${fmtSize(r.size)}${r.truncated ? ' (cut at 10 MB)' : ''}</span>` +
        `<span class="muted" title="${esc(r.final_url)}">${esc(r.final_url)}</span>`;
    box.className = 'resp' + ($('wrapResp').checked ? ' wrap' : '');

    if (view === 'headers') {
        box.className = 'resp wrap';
        box.innerHTML = '<table class="hdr">' + r.headers.map(([n, v]) => `<tr><td>${esc(n)}</td><td>${esc(v)}</td></tr>`).join('') + '</table>';
        return;
    }
    if (view === 'hex') { box.className = 'resp'; box.innerHTML = hexDump(r.body_b64 || '') + (r.size > 262144 ? '<span class="muted">… first 256 KB shown</span>' : ''); return; }

    const status = `<span class="t-v">${esc(r.proto)}</span> <span class="st ${sCls(r.status_code)}">${r.status_code}</span> <span class="t-st">${esc(r.status_text)}</span>`;
    const head = status + r.headers.map(([n, v]) => '\n' + hdrHL(n, v)).join('') + '\n\n';
    let body;
    if (r.binary) body = `<span class="muted">[binary content, ${fmtSize(r.size)}: open the Hex tab]</span>`;
    else if (view === 'raw' || r.body.length >= 1e6) body = esc(r.body);
    else {
        const ct = (r.headers.find(h => h[0].toLowerCase() === 'content-type') || ['', ''])[1];
        body = esc(r.body);
        if (/json/i.test(ct) || looksJson(r.body)) { try { body = jsonHL(prettyJson(r.body)); } catch { /* invalid JSON: show as is */ } }
        else if (/html|xml|svg/i.test(ct)) body = xmlHL(r.body);
    }
    box.innerHTML = head + body;
}

function updateNav() {
    $('histPos').textContent = hist.length ? `#${hist[cur].n}  (${cur + 1}/${hist.length})` : '–';
    $('histPrev').disabled = cur <= 0;
    $('histNext').disabled = cur >= hist.length - 1;
    $('inflight').textContent = inflight ? `${inflight}…` : '';
}

function showEntry(i) {
    cur = Math.max(0, Math.min(hist.length - 1, i));
    const e = hist[cur];
    if (e) { $('reqText').value = e.raw; $('target').value = e.target; syncEditor(); }   // Burp restores the request as well
    renderResp(); updateNav();
}

/* ================= sending (never blocks: Ctrl+Enter can be pressed again and again) ================= */
function options() {
    return { target: $('target').value.trim(), raw: $('reqText').value, insecure: $('optTls').checked, follow: $('optRedir').checked, timeout: +$('optTimeout').value || 30 };
}

function send() {
    const body = options();
    const entry = { n: ++seq, raw: body.raw, target: body.target, resp: null };
    hist.push(entry);
    if (hist.length > 100) hist.shift();
    cur = hist.length - 1; inflight++;
    renderResp(); updateNav();
    post('send', body)
        .then(r => { entry.resp = r; })
        .catch(e => { entry.resp = { error: e.message }; })
        .finally(() => {
            inflight--;
            if (hist[cur] === entry) renderResp();   // responses of older requests only fill their own history entry
            updateNav();
        });
}

/* ================= editor <-> request state ================= */
function applyRequest(p) {
    $('target').value = p.target;
    $('reqText').value = p.raw;
    $('optTls').checked = !!p.insecure; $('optRedir').checked = !!p.follow;
    $('optTimeout').value = p.timeout || 30;
    syncEditor();
}

function fmtBody(pretty) {
    const t = $('reqText'), i = t.value.indexOf('\n\n');
    if (i < 0 || !t.value.slice(i + 2).trim()) { toast('The request has no body', true); return; }
    const head = t.value.slice(0, i + 2), body = t.value.slice(i + 2);
    try { t.value = head + (pretty ? prettyJson(body) : JSON.stringify(JSON.parse(body))); syncEditor(); }
    catch { toast('The body is not valid JSON', true); }
}

/* ================= sidebar: add by pasting a cURL command ================= */
async function addCurl() {
    const cmd = $('addIn').value.trim();
    if (!cmd) return;
    try {
        const r = await post('requests/import', { command: cmd });   // the Go parser parses it and stores it in one call
        selId = r.saved.id;
        await loadSaved();
        applyRequest(r.saved);
        $('addIn').value = '';
        toast(r.warnings.length ? r.warnings.join(' · ') : 'Request added. Press Ctrl + Enter to send.');
        $('reqText').focus();
    } catch (e) { toast(e.message, true); }
}

async function loadSaved() { try { saved = await api('requests'); } catch { saved = []; } renderSaved(); }

function renderSaved() {
    const q = $('savedFilter').value.trim().toLowerCase();
    $('savedCount').textContent = saved.length;
    const list = saved.filter(s => (s.method + ' ' + s.domain + ' ' + s.path).toLowerCase().includes(q));
    $('savedList').innerHTML = list.map(s => `<div class="item${s.id === selId ? ' sel' : ''}" data-id="${esc(s.id)}"><span class="mth m-${esc(s.method)}">${esc(s.method)}</span>` +
        `<div class="tx"><div class="h">${esc(s.domain)}</div><div class="p" title="${esc(s.path)}">${esc(s.path)}</div></div><button class="x" data-del="${esc(s.id)}" title="Delete">×</button></div>`).join('') ||
        `<div class="empty">${saved.length ? 'No matches' : 'Paste a cURL command above to add your first request.'}</div>`;
}

async function save() {
    try {
        let s;
        if (selId && saved.some(x => x.id === selId)) s = await api('requests?id=' + encodeURIComponent(selId), { method: 'PUT', body: JSON.stringify(options()) });
        else s = await post('requests', options());
        selId = s.id; await loadSaved(); toast('Saved');
    } catch (e) { toast(e.message, true); }
}

/* ================= init ================= */
window.addEventListener('DOMContentLoaded', () => {
    const ta = $('reqText');
    ta.addEventListener('input', syncEditor);
    ta.addEventListener('scroll', () => { $('reqHl').scrollTop = ta.scrollTop; $('reqHl').scrollLeft = ta.scrollLeft; });
    ta.addEventListener('keydown', e => { if (e.key === 'Tab') { e.preventDefault(); document.execCommand('insertText', false, '    '); } });

    // Ctrl/Cmd + Enter sends from anywhere (adds when the sidebar box has focus).
    // Holding the keys does not repeat, but pressing them again and again sends again immediately.
    addEventListener('keydown', e => {
        if (!(e.ctrlKey || e.metaKey) || e.key !== 'Enter') return;
        e.preventDefault();
        if (e.repeat) return;
        if (document.activeElement === $('addIn')) addCurl(); else send();
    });

    // Pasting a full cURL command into the sidebar box adds it right away.
    $('addIn').addEventListener('paste', () => setTimeout(() => { if (/^\s*(\$\s*)?curl(\.exe)?\b/i.test($('addIn').value)) addCurl(); }, 0));
    $('addBtn').onclick = addCurl;

    $('sendBtn').onclick = send;
    $('saveBtn').onclick = save;
    $('themeBtn').onclick = () => setTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
    $('prettyBody').onclick = () => fmtBody(true);
    $('minBody').onclick = () => fmtBody(false);
    $('histPrev').onclick = () => showEntry(cur - 1);
    $('histNext').onclick = () => showEntry(cur + 1);
    $('copyBtn').onclick = async () => {
        try { const r = await post('tocurl', options()); await navigator.clipboard.writeText(r.command); toast('Copied as cURL'); }
        catch (e) { toast(e.message, true); }
    };

    $('savedList').onclick = async e => {
        const del = e.target.closest('[data-del]');
        if (del) {
            await api('requests?id=' + encodeURIComponent(del.dataset.del), { method: 'DELETE' });
            if (selId === del.dataset.del) selId = null;
            await loadSaved(); return;
        }
        const it = e.target.closest('.item');
        const s = it && saved.find(x => x.id === it.dataset.id);
        if (s) { selId = s.id; applyRequest(s); renderSaved(); }
    };
    $('clearSaved').onclick = async () => { await api('requests?all=1', { method: 'DELETE' }); selId = null; await loadSaved(); };
    $('savedFilter').oninput = renderSaved;
    $('wrapReq').onchange = e => $('editor').classList.toggle('wrap', e.target.checked);
    $('wrapResp').onchange = renderResp;
    $('respTabs').onclick = e => {
        const b = e.target.closest('button'); if (!b) return;
        view = b.dataset.v;
        document.querySelectorAll('#respTabs button').forEach(x => x.classList.toggle('active', x === b));
        renderResp();
    };
    document.addEventListener('click', e => {   // close the Options menu when clicking elsewhere
        const m = $('optMenu');
        if (m.open && !m.contains(e.target)) m.open = false;
    });

    applyRequest({ target: 'https://example.com', raw: 'GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n', insecure: true, follow: false, timeout: 30 });
    renderResp(); updateNav(); loadSaved();
});
