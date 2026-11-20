// ShieldLocal demo file – every flagged line below is intentionally vulnerable.
// Open this file in VS Code with the extension installed to see the squiggles.
const express = require('express');
const crypto = require('crypto');
const { exec } = require('child_process');
const app = express();

const dbPassword = "Sup3rS3cret!";                       // hard-coded credential

app.get('/user', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id);   // SQL injection
  const digest = crypto.createHash('md5').update(req.query.p);  // weak hash
  exec('ping ' + req.query.host);                               // command injection
  document.getElementById('out').innerHTML = req.query.name;    // XSS
  res.redirect(req.query.next);                                 // open redirect
});

const agent = { rejectUnauthorized: false };                    // TLS disabled
const token = Math.random().toString(36);                       // weak session token
