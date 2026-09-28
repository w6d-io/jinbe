// Counting reverse proxy: forwards to a target and counts requests, so a benchmark can report
// upstream calls per API request. GET /__count returns and resets the counter.
import http from 'node:http'
const [, , listen, target] = process.argv
let n = 0
http.createServer((req, res) => {
  if (req.url === '/__count') { res.end(String(n)); n = 0; return }
  n++
  const up = http.request(target + req.url, { method: req.method, headers: req.headers }, (r) => {
    res.writeHead(r.statusCode, r.headers); r.pipe(res)
  })
  up.on('error', () => { res.writeHead(502); res.end() })
  req.pipe(up)
}).listen(Number(listen))
