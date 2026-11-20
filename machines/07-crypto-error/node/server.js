// Acme reports microservice - intentionally vulnerable. Training only.
// WSTG-ERRH-02: unhandled exceptions surface full Express/Node stack traces
// (source paths, line numbers, framework internals) in development mode.
const express = require('express');
const app = express();

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Debug endpoint left enabled: runtime versions and environment disclosure.
app.get('/debug/vars', (req, res) => {
  res.json({
    versions: process.versions,
    express: require('express/package.json').version,
    argv: process.argv,
    env: process.env,
  });
});

// TypeError deep inside a request handler -> full stack in the response.
app.get('/crash', (req, res) => {
  const reportId = req.query.id || 'r-4213';
  const report = lookupReport(reportId); // returns undefined
  res.json({ owner: report.owner.name }); // throws TypeError
});

function lookupReport(id) {
  const db = { 'r-1': { owner: { name: 'alice' } } };
  return db[id];
}

// SyntaxError from unvalidated input -> stack trace including parser frames.
app.get('/parse', (req, res) => {
  const payload = JSON.parse(req.query.data);
  res.json(payload);
});

app.listen(5000, '0.0.0.0', () => {
  console.log('acme-reports listening on :5000 (development mode)');
});