// WSTG-INJT-05 (05.8) - INTENTIONALLY VULNERABLE client-side SQL.
// The URL parameter `name` is concatenated straight into an alasql statement
// that runs entirely in the browser. A debug sink (window.__sqlDebug and a
// POST to /clientsql/sink) records the exact executed statement + rows so the
// injection can be asserted by an automated probe.
(function () {
  // "database" seeded client-side
  alasql('CREATE TABLE users (name STRING, role STRING)');
  alasql("INSERT INTO users VALUES ('alice','user'),('bob','user'),('admin','admin')");
  alasql('CREATE TABLE vault (secret STRING)');
  alasql("INSERT INTO vault VALUES ('WSTG-M04{client_side_alasql}')");

  var params = new URLSearchParams(location.search);
  var name = params.get('name') || '';
  var token = params.get('token') || 'default';

  // VULNERABLE: string concatenation into client-side SQL
  var sql = "SELECT name,role FROM users WHERE name = '" + name + "'";
  var rows = [];
  var error = null;
  try {
    rows = alasql(sql);
  } catch (e) {
    error = String(e);
  }

  // render
  document.getElementById('sql').textContent = sql;
  var out = document.getElementById('out');
  if (error) {
    out.textContent = 'Error: ' + error;
  } else {
    var html = '<table><tr><th>col1</th><th>col2</th></tr>';
    rows.forEach(function (r) {
      var vals = Object.values(r);
      html += '<tr><td>' + vals[0] + '</td><td>' + (vals[1] || '') + '</td></tr>';
    });
    html += '</table>';
    out.innerHTML = html;
  }

  // debug sink: exact executed statement + result rows
  window.__sqlDebug = { sql: sql, rows: rows, error: error, token: token };
  fetch('/clientsql/sink', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: token, sql: sql, rows: rows })
  }).catch(function () {});
})();