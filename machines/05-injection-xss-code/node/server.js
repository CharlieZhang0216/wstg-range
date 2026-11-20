/* M05 Node target - WSTG-INJT-22 prototype pollution.
 *
 * A hand-rolled recursive merge with no own-property / __proto__ guard lets a
 * JSON body write into Object.prototype. The effect is GLOBAL and persists for
 * every later request, including requests that never touched /settings:
 *   - GET /admin   : a fresh {name:'guest'} inherits isAdmin === true
 *   - GET /profile : a fresh {} inherits the polluted defaults
 *   - POST /render : ejs 3.1.6 picks up a polluted outputFunctionName -> RCE
 */
const http = require('http');
const child_process = require('child_process');
const ejs = require('ejs');

const FLAG = process.env.FLAG_PROTO || 'WSTG-M05{prototype_pollution}';
const PORT = 3000;

function isObjectish(v) {
  return v !== null && (typeof v === 'object' || typeof v === 'function');
}

// VULNERABLE: recurses into __proto__ and constructor.prototype.
function merge(dst, src) {
  for (const key in src) {
    const sv = src[key];
    if (isObjectish(sv)) {
      if (!isObjectish(dst[key])) dst[key] = {};
      merge(dst[key], sv);
    } else {
      dst[key] = sv;
    }
  }
  return dst;
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      try { resolve(JSON.parse(raw || '{}')); } catch (e) { resolve({}); }
    });
  });
}

function send(res, code, obj, headers) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(code, Object.assign({
    'Content-Type': typeof obj === 'string' ? 'text/html' : 'application/json',
    'Content-Length': Buffer.byteLength(body),
  }, headers || {}));
  res.end(body);
}

const POLLUTABLE = ['isAdmin', 'role', 'theme', 'outputFunctionName', 'client',
                    'escapeFunction', 'debug', 'status'];

function pollutedKeys() {
  return POLLUTABLE.filter((k) => Object.prototype.hasOwnProperty.call(Object.prototype, k));
}

const server = http.createServer(async (req, res) => {
  const path = req.url.split('?')[0];

  if (path === '/health') return send(res, 200, { status: 'ok', service: 'm05-node' });

  if (path === '/') {
    return send(res, 200, `<html><body><h1>M05 Node prototype-pollution target</h1>
<ul>
<li>POST /settings  - JSON body deep-merged into a fresh object (vulnerable merge)</li>
<li>GET  /admin     - authorisation reads isAdmin from a fresh {name:'guest'}</li>
<li>GET  /profile   - unrelated endpoint reading defaults from a fresh {}</li>
<li>POST /render    - ejs 3.1.6 render (outputFunctionName gadget)</li>
<li>POST /reset     - lab helper: removes polluted prototype keys</li>
</ul>
<pre>curl -XPOST :8520/settings -H 'Content-Type: application/json' \\
  -d '{"__proto__":{"isAdmin":true}}'
curl :8520/admin      # now 200 for a brand-new request</pre></body></html>`);
  }

  if (path === '/settings' && req.method === 'POST') {
    const body = await readBody(req);
    const target = {};                 // per-request object ...
    merge(target, body);               // ... but the merge escapes into Object.prototype
    return send(res, 200, {
      merged: true,
      local_object: target,
      prototype_polluted: pollutedKeys(),
      global_isAdmin: ({}).isAdmin === true,
    });
  }

  // Unrelated request: no settings object is involved, the check reads a
  // property that only exists because Object.prototype was polluted.
  if (path === '/admin') {
    const user = { name: 'guest' };
    if (user.isAdmin) {
      return send(res, 200, { user: user.name, role: 'admin', flag: FLAG,
                              inherited_isAdmin: user.isAdmin },
                  { 'X-Proto-Polluted': 'true' });
    }
    return send(res, 403, { user: user.name, denied: true, isAdmin: user.isAdmin === true });
  }

  if (path === '/profile') {
    const prefs = {};                  // fresh object, unrelated to /settings
    return send(res, 200, {
      theme: prefs.theme || 'light',
      role: prefs.role || 'user',
      isAdmin: prefs.isAdmin === true,
      polluted_keys: pollutedKeys(),
    });
  }

  if (path === '/render' && req.method === 'POST') {
    const body = await readBody(req);
    try {
      const out = ejs.render('<h1><%= message %></h1>', { message: body.message || 'hello' });
      return send(res, 200, { rendered: out });
    } catch (e) {
      return send(res, 500, { error: String(e && e.message || e) });
    }
  }

  if (path === '/reset' && req.method === 'POST') {
    for (const k of POLLUTABLE) delete Object.prototype[k];
    return send(res, 200, { reset: true, polluted_keys: pollutedKeys(),
                            isAdmin: ({}).isAdmin === true });
  }

  return send(res, 404, { error: 'not found', path });
});

server.listen(PORT, '0.0.0.0', () => console.log('m05-node listening on ' + PORT));