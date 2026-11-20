'use strict';
/**
 * ShieldLocal rule catalogue.
 * Every rule is evaluated line by line, 100% offline.
 *
 * rule = {
 *   id, title, severity, category, cwe, langs (null = every language),
 *   pattern (global RegExp), message, remediation,
 *   filter?(ctx) -> boolean       // return false to drop a match
 *   fix?: { title, apply(m, ctx) -> string, when?(ctx) -> boolean }  // replaces the matched text
 * }
 */

const JS = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'vue', 'svelte'];
const PY = ['python'];
const PHP = ['php'];
const JAVA = ['java'];
const GO = ['go'];
const CS = ['csharp'];
const RB = ['ruby'];
const SH = ['shellscript', 'dockerfile'];
const ENVLIKE = ['dotenv', 'properties', 'ini', 'shellscript', 'dockerfile', 'yaml', 'plaintext', 'toml'];

const SQLKW = String.raw`(?:SELECT\b[^'"\`\n]*?\bFROM|INSERT\s+INTO|UPDATE\b[^'"\`\n]*?\bSET|DELETE\s+FROM)`;

function entropy(s) {
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  let h = 0;
  for (const k in f) {
    const p = f[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function isPlaceholder(v) {
  if (!v) return true;
  const s = v.trim();
  if (/^(?:x+|\*+|\.+|-+|_+|0+)$/i.test(s)) return true;
  if (/^(?:<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|\$[A-Za-z_][\w]*|\$\(.*\))$/.test(s)) return true;
  if (/(?:process\.env|os\.environ|getenv|System\.getenv|ENV\[)/i.test(s)) return true;
  if (/(?:^|[_-])(?:your|my|example|sample|dummy|placeholder|changeme|change_me|replace|todo|fixme|redacted|insert)(?:[_-]|$)/i.test(s)) return true;
  if (/^(?:password|passwd|secret|token|apikey|api_key|test|testing|none|null|undefined|required|string|number|bearer)$/i.test(s)) return true;
  if (/x{5,}/i.test(s)) return true;
  return false;
}

const envName = (name) => name.replace(/[^A-Za-z0-9]+/g, '_').replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase();

const RULES = [
  /* ─────────────── Secrets ─────────────── */
  {
    id: 'secret-aws-access-key', title: 'AWS access key ID', severity: 'critical', category: 'secrets', cwe: 798,
    pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b/g,
    message: 'An AWS access key ID is hard-coded in source.',
    remediation: 'Revoke the key in IAM, then load credentials from environment variables, AWS SSO or a secrets manager.',
    filter: ({ m }) => !/EXAMPLE$/.test(m[0]),
  },
  {
    id: 'secret-aws-secret-key', title: 'AWS secret access key', severity: 'critical', category: 'secrets', cwe: 798,
    pattern: /\baws.{0,30}?secret.{0,30}?['"]([A-Za-z0-9/+=]{40})['"]/gi,
    message: 'An AWS secret access key appears to be hard-coded.',
    remediation: 'Rotate the key immediately and move it to a secrets manager or environment variable.',
    filter: ({ m }) => !isPlaceholder(m[1]) && entropy(m[1]) > 3.5,
  },
  {
    id: 'secret-github-token', title: 'GitHub token', severity: 'critical', category: 'secrets', cwe: 798,
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g,
    message: 'A GitHub personal-access / OAuth token is hard-coded.',
    remediation: 'Revoke the token at github.com/settings/tokens and use GITHUB_TOKEN or a secret store.',
  },
  {
    id: 'secret-slack-token', title: 'Slack token', severity: 'high', category: 'secrets', cwe: 798,
    pattern: /\bxox[abposr]-[0-9A-Za-z-]{10,72}\b/g,
    message: 'A Slack API token is hard-coded.',
    remediation: 'Revoke the token in the Slack admin console and read it from a secret store.',
  },
  {
    id: 'secret-stripe-key', title: 'Stripe live secret key', severity: 'critical', category: 'secrets', cwe: 798,
    pattern: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/g,
    message: 'A live Stripe secret key is hard-coded.',
    remediation: 'Roll the key in the Stripe dashboard and inject it at runtime.',
  },
  {
    id: 'secret-google-api-key', title: 'Google API key', severity: 'high', category: 'secrets', cwe: 798,
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    message: 'A Google API key is embedded in source.',
    remediation: 'Restrict or rotate the key in Google Cloud Console and keep it out of the repository.',
  },
  {
    id: 'secret-private-key', title: 'Private key', severity: 'critical', category: 'secrets', cwe: 321,
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    message: 'A private key is committed to source.',
    remediation: 'Remove the key from history, treat it as compromised and generate a new key pair.',
  },
  {
    id: 'secret-jwt', title: 'JSON Web Token', severity: 'medium', category: 'secrets', cwe: 522,
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    message: 'A signed JWT is hard-coded; it may grant access if still valid.',
    remediation: 'Remove it and make sure the token is expired or revoked.',
  },
  {
    id: 'secret-connection-string', title: 'Credentials in connection string', severity: 'high', category: 'secrets', cwe: 798,
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|mssql|sqlserver|ftp|sftp|smtp):\/\/[^\s:@/'"`]+:([^\s:@/'"`]{3,})@[^\s'"`]+/gi,
    message: 'A connection string embeds a username and password.',
    remediation: 'Move the credentials to environment variables and build the URL at runtime.',
    filter: ({ m }) => !isPlaceholder(m[1]),
  },
  {
    id: 'secret-hardcoded-credential', title: 'Hard-coded credential', severity: 'high', category: 'secrets', cwe: 798,
    pattern: /\b((?:[A-Za-z_][\w.-]*?)?(?:passw(?:or)?d|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret|token))\s*[:=]\s*(['"])([^'"\s]{8,})\2/gi,
    message: 'A password, token or API key is assigned a literal value.',
    remediation: 'Read the value from an environment variable or a secrets manager instead of source code.',
    filter: ({ m, lang }) => {
      const v = m[3];
      if (isPlaceholder(v)) return false;
      if (/^[\w-]+\.[\w-]+(?:\.[\w-]+)*$/.test(v) && !/\d/.test(v)) return false; // e.g. config.key.path
      if (/passw|pwd/i.test(m[1])) return true;
      return entropy(v) >= 3.0 && lang !== 'html';
    },
    fix: {
      title: 'Replace with environment variable',
      when: ({ lang }) => JS.includes(lang) || PY.includes(lang),
      apply: (m, { lang }) => {
        const lit = m[3].length + 2;
        const prefix = m[0].slice(0, m[0].length - lit);
        const key = envName(m[1]);
        return prefix + (PY.includes(lang) ? `os.environ["${key}"]` : `process.env.${key}`);
      },
    },
  },
  {
    id: 'secret-env-assignment', title: 'Secret value in config file', severity: 'high', category: 'secrets', cwe: 798,
    langs: ENVLIKE,
    pattern: /^\s*(?:export\s+|ENV\s+|ARG\s+)?([A-Za-z][A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Za-z0-9_]*)\s*[=:]\s*['"]?([^\s'"#]{8,})['"]?\s*$/gim,
    message: 'A secret value is stored in plain text in a config file.',
    remediation: 'Keep the file out of version control (.gitignore) and inject the value from a secret store.',
    filter: ({ m }) => !isPlaceholder(m[2]),
  },

  /* ─────────────── Code execution & injection ─────────────── */
  {
    id: 'code-eval', title: 'Use of eval()', severity: 'high', category: 'injection', cwe: 95,
    langs: [...JS, ...PY, ...PHP, ...RB],
    pattern: /(?<![\w.$])eval\s*\(/g,
    message: 'eval() executes arbitrary code and is a common injection vector.',
    remediation: 'Replace with JSON.parse, ast.literal_eval or an explicit lookup table.',
  },
  {
    id: 'code-new-function', title: 'Dynamic Function constructor', severity: 'high', category: 'injection', cwe: 95,
    langs: JS, pattern: /\bnew\s+Function\s*\(/g,
    message: 'new Function() compiles strings into code at runtime.',
    remediation: 'Avoid generating code from strings; use closures or data-driven logic.',
  },
  {
    id: 'code-timer-string', title: 'String passed to setTimeout/setInterval', severity: 'medium', category: 'injection', cwe: 95,
    langs: JS, pattern: /\bset(?:Timeout|Interval)\s*\(\s*(['"`])/g,
    message: 'Passing a string behaves like eval().',
    remediation: 'Pass a function reference instead of a string.',
  },
  {
    id: 'code-python-exec', title: 'Use of exec()', severity: 'high', category: 'injection', cwe: 95,
    langs: PY, pattern: /(?<![\w.])exec\s*\(/g,
    message: 'exec() runs arbitrary Python code.',
    remediation: 'Avoid dynamic execution; dispatch through a dict of allowed callables.',
  },
  {
    id: 'cmd-node-exec', title: 'Shell command built from variable', severity: 'high', category: 'injection', cwe: 78,
    langs: JS,
    pattern: /(?<![\w$.])(?:(?:child_process|cp)\s*\.\s*)?(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$.]*\s*[,)])/g,
    message: 'A shell command is assembled from non-constant input (command injection).',
    remediation: 'Use execFile/spawn with an argument array and validate every input.',
    filter: ({ m, text }) => /child_process|\bcp\./.test(m[0]) || /child_process/.test(text),
  },
  {
    id: 'cmd-node-shell-true', title: 'spawn with shell: true', severity: 'medium', category: 'injection', cwe: 78,
    langs: JS, pattern: /\bshell\s*:\s*true\b/g,
    message: 'Running a child process through a shell enables metacharacter injection.',
    remediation: 'Drop shell: true and pass arguments as an array.',
    filter: ({ text }) => /spawn|exec/.test(text),
  },
  {
    id: 'cmd-python-shell', title: 'subprocess with shell=True', severity: 'high', category: 'injection', cwe: 78,
    langs: PY, pattern: /\bsubprocess\.\w+\s*\([^)\n]*\bshell\s*=\s*True/g,
    message: 'shell=True lets untrusted input run arbitrary shell commands.',
    remediation: 'Pass a list of arguments and omit shell=True.',
  },
  {
    id: 'cmd-python-os-system', title: 'os.system / os.popen', severity: 'high', category: 'injection', cwe: 78,
    langs: PY, pattern: /\bos\.(?:system|popen)\s*\(/g,
    message: 'Commands run through the shell are vulnerable to injection.',
    remediation: 'Use subprocess.run([...], check=True) with a fixed argument list.',
  },
  {
    id: 'cmd-php-exec', title: 'Shell execution with variable', severity: 'high', category: 'injection', cwe: 78,
    langs: PHP, pattern: /\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*[^)\n]*\$\w+/g,
    message: 'A PHP shell function receives a variable (command injection).',
    remediation: 'Use escapeshellarg()/escapeshellcmd() or avoid shelling out.',
  },
  {
    id: 'cmd-java-runtime-exec', title: 'Runtime.exec()', severity: 'high', category: 'injection', cwe: 78,
    langs: JAVA, pattern: /\bRuntime\.getRuntime\(\)\s*\.exec\s*\(/g,
    message: 'Runtime.exec can lead to OS command injection.',
    remediation: 'Use ProcessBuilder with a fixed argument list and validate inputs.',
  },
  {
    id: 'cmd-go-shell', title: 'exec.Command via shell', severity: 'high', category: 'injection', cwe: 78,
    langs: GO, pattern: /\bexec\.Command\s*\(\s*"(?:sh|bash|cmd(?:\.exe)?)"\s*,\s*"(?:-c|\/c)"/g,
    message: 'Invoking a shell with -c opens the door to command injection.',
    remediation: 'Call the target binary directly with separate arguments.',
  },
  {
    id: 'cmd-ruby-shell', title: 'Shell command with interpolation', severity: 'high', category: 'injection', cwe: 78,
    langs: RB, pattern: /\b(?:system|exec)\s*\(?\s*["'][^"'\n]*#\{|`[^`\n]*#\{[^}\n]+\}[^`\n]*`/g,
    message: 'String interpolation inside a shell command enables injection.',
    remediation: 'Use the multi-argument form: system("cmd", arg).',
  },
  {
    id: 'sql-concat', title: 'SQL built by string concatenation', severity: 'high', category: 'injection', cwe: 89,
    langs: [...JS, ...PY, ...PHP, ...JAVA, ...CS, ...GO, ...RB],
    pattern: new RegExp(String.raw`\b${SQLKW}\b[^'"\`\n]*?(['"\`])\s*(?:\+|%\s*[\w(]|\.format\s*\()`, 'gi'),
    message: 'A SQL statement is concatenated or formatted with dynamic values (SQL injection).',
    remediation: 'Use parameterised queries / prepared statements instead of string building.',
  },
  {
    id: 'sql-template', title: 'SQL built with template interpolation', severity: 'high', category: 'injection', cwe: 89,
    langs: [...JS, ...CS],
    pattern: new RegExp(String.raw`\`[^\`\n]*\b${SQLKW}\b[^\`\n]*\$\{[^}\n]+\}`, 'gi'),
    message: 'Interpolating values into a SQL template literal allows injection.',
    remediation: 'Use placeholders ($1, ?) and pass values separately.',
  },
  {
    id: 'sql-fstring', title: 'SQL built with f-string', severity: 'high', category: 'injection', cwe: 89,
    langs: PY,
    pattern: new RegExp(String.raw`\bf(["'])(?:(?!\1)[^\n])*?\b${SQLKW}\b(?:(?!\1)[^\n])*?\{[^}\n]+\}`, 'gi'),
    message: 'An f-string builds SQL from variables (SQL injection).',
    remediation: 'Use cursor.execute(sql, params) with placeholders.',
  },
  {
    id: 'sql-ruby-interp', title: 'SQL built with interpolation', severity: 'high', category: 'injection', cwe: 89,
    langs: RB, pattern: /\b(?:where|find_by_sql|execute|exists\?)\s*\(\s*"[^"\n]*#\{/g,
    message: 'Interpolated SQL in ActiveRecord is injectable.',
    remediation: 'Use where("name = ?", name) or hash conditions.',
  },
  {
    id: 'sql-php-query', title: 'mysql_query with variable', severity: 'high', category: 'injection', cwe: 89,
    langs: PHP, pattern: /\b(?:mysql_query|mysqli_query|pg_query)\s*\([^)\n]*\$/g,
    message: 'A query function receives a variable directly.',
    remediation: 'Switch to PDO or mysqli prepared statements.',
  },
  {
    id: 'nosql-injection', title: 'Request body passed to query', severity: 'high', category: 'injection', cwe: 943,
    langs: JS, pattern: /\b(?:find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany)\s*\(\s*req\.(?:body|query)\s*[,)]/g,
    message: 'Unvalidated request data is used as a NoSQL query object.',
    remediation: 'Validate input and pick explicit fields; reject objects with $ operators.',
  },
  {
    id: 'xss-innerhtml', title: 'Unsafe innerHTML assignment', severity: 'medium', category: 'xss', cwe: 79,
    langs: [...JS, 'html'], pattern: /\.(?:innerHTML|outerHTML)\s*\+?=(?!=)/g,
    message: 'Assigning dynamic content to innerHTML can execute injected scripts (XSS).',
    remediation: 'Use textContent, or sanitise with DOMPurify before inserting HTML.',
    filter: ({ lineText, m }) => {
      const rhs = lineText.slice(m.index + m[0].length).trim();
      return !/^(['"`])[^'"`$]*\1\s*;?\s*(?:\/\/.*)?$/.test(rhs);
    },
  },
  {
    id: 'xss-insert-adjacent', title: 'insertAdjacentHTML', severity: 'medium', category: 'xss', cwe: 79,
    langs: [...JS, 'html'], pattern: /\.insertAdjacentHTML\s*\(/g,
    message: 'Raw HTML insertion can introduce XSS.',
    remediation: 'Sanitise the HTML first or build nodes with createElement.',
  },
  {
    id: 'xss-document-write', title: 'document.write()', severity: 'medium', category: 'xss', cwe: 79,
    langs: [...JS, 'html'], pattern: /\bdocument\.write(?:ln)?\s*\(/g,
    message: 'document.write injects raw markup and blocks parsing.',
    remediation: 'Use DOM APIs such as appendChild with textContent.',
  },
  {
    id: 'xss-react-dangerous', title: 'dangerouslySetInnerHTML', severity: 'medium', category: 'xss', cwe: 79,
    langs: JS, pattern: /\bdangerouslySetInnerHTML\b/g,
    message: 'Bypasses React escaping; untrusted HTML leads to XSS.',
    remediation: 'Sanitise with DOMPurify or render as text.',
  },
  {
    id: 'xss-vue-vhtml', title: 'v-html directive', severity: 'medium', category: 'xss', cwe: 79,
    langs: ['vue', 'html'], pattern: /\bv-html\s*=/g,
    message: 'v-html renders raw HTML and is an XSS risk with untrusted data.',
    remediation: 'Use text interpolation {{ }} or sanitise first.',
  },
  {
    id: 'xss-php-echo', title: 'Unescaped request data echoed', severity: 'high', category: 'xss', cwe: 79,
    langs: PHP, pattern: /\b(?:echo|print)\b[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b/g,
    message: 'User input is printed without escaping.',
    remediation: 'Wrap output in htmlspecialchars($v, ENT_QUOTES, "UTF-8").',
    filter: ({ lineText }) => !/htmlspecialchars|htmlentities|esc_html/.test(lineText),
  },
  {
    id: 'xss-django-mark-safe', title: 'mark_safe()', severity: 'low', category: 'xss', cwe: 79,
    langs: PY, pattern: /\bmark_safe\s*\(/g,
    message: 'Marks content as safe HTML, disabling auto-escaping.',
    remediation: 'Only use on fully trusted, sanitised strings.',
  },
  {
    id: 'xss-jinja-autoescape', title: 'Template autoescape disabled', severity: 'medium', category: 'xss', cwe: 79,
    langs: PY, pattern: /\bautoescape\s*=\s*False\b/g,
    message: 'Disabling autoescape allows HTML injection in templates.',
    remediation: 'Leave autoescape enabled (autoescape=True).',
  },
  {
    id: 'ssti-flask', title: 'render_template_string with dynamic input', severity: 'high', category: 'injection', cwe: 1336,
    langs: PY, pattern: /\brender_template_string\s*\(\s*(?:f['"]|['"][^'"\n]*['"]\s*[%+])/g,
    message: 'Dynamic template source can lead to server-side template injection.',
    remediation: 'Use render_template with static template files.',
  },
  {
    id: 'ruby-html-safe', title: 'html_safe / raw', severity: 'medium', category: 'xss', cwe: 79,
    langs: RB, pattern: /\.html_safe\b|\braw\s*\(/g,
    message: 'Bypasses Rails output escaping.',
    remediation: 'Use sanitize() or escape the value.',
  },

  /* ─────────────── Deserialisation ─────────────── */
  {
    id: 'deser-python', title: 'Unsafe deserialisation', severity: 'high', category: 'injection', cwe: 502,
    langs: PY, pattern: /\b(?:pickle|cPickle|dill|marshal|shelve)\.loads?\s*\(/g,
    message: 'Loading untrusted pickle/marshal data can execute arbitrary code.',
    remediation: 'Use JSON or another data-only format; never unpickle untrusted bytes.',
  },
  {
    id: 'deser-yaml', title: 'yaml.load without safe loader', severity: 'high', category: 'injection', cwe: 502,
    langs: PY, pattern: /\byaml\.load\s*\(/g,
    message: 'yaml.load can construct arbitrary Python objects.',
    remediation: 'Use yaml.safe_load().',
    filter: ({ lineText }) => !/Safe(?:Loader)?|CSafeLoader/.test(lineText),
    fix: {
      title: 'Use yaml.safe_load()',
      when: ({ lineText }) => !/Loader/.test(lineText),
      apply: () => 'yaml.safe_load(',
    },
  },
  {
    id: 'deser-php', title: 'unserialize() on variable', severity: 'high', category: 'injection', cwe: 502,
    langs: PHP, pattern: /\bunserialize\s*\(\s*\$/g,
    message: 'Unserialising user data allows object injection.',
    remediation: 'Use json_decode() or pass allowed_classes => false.',
  },
  {
    id: 'deser-java', title: 'ObjectInputStream', severity: 'high', category: 'injection', cwe: 502,
    langs: JAVA, pattern: /\bnew\s+ObjectInputStream\s*\(/g,
    message: 'Java native deserialisation of untrusted data leads to RCE.',
    remediation: 'Use a data-only format or a strict ObjectInputFilter allow-list.',
  },
  {
    id: 'deser-dotnet', title: 'BinaryFormatter', severity: 'high', category: 'injection', cwe: 502,
    langs: CS, pattern: /\bnew\s+BinaryFormatter\s*\(/g,
    message: 'BinaryFormatter is insecure and obsolete.',
    remediation: 'Use System.Text.Json or DataContractSerializer.',
  },
  {
    id: 'deser-ruby', title: 'Marshal.load / YAML.load', severity: 'high', category: 'injection', cwe: 502,
    langs: RB, pattern: /\b(?:Marshal|YAML)\.load\s*\(/g,
    message: 'Loading untrusted data can instantiate arbitrary objects.',
    remediation: 'Use YAML.safe_load or JSON.parse.',
  },

  /* ─────────────── Web / request handling ─────────────── */
  {
    id: 'web-path-traversal', title: 'File access from request data', severity: 'high', category: 'injection', cwe: 22,
    langs: JS,
    pattern: /\b(?:readFile|readFileSync|createReadStream|sendFile|unlink|unlinkSync|writeFile|writeFileSync)\s*\([^)\n]*\breq\.(?:params|query|body)\b/g,
    message: 'A file path is derived from request input (path traversal).',
    remediation: 'Resolve against a base directory and reject paths that escape it.',
  },
  {
    id: 'web-path-traversal-py', title: 'send_file from request data', severity: 'high', category: 'injection', cwe: 22,
    langs: PY, pattern: /\bsend_file\s*\([^)\n]*request\.(?:args|form|values|json)/g,
    message: 'A file path comes straight from request data.',
    remediation: 'Use send_from_directory and secure_filename.',
  },
  {
    id: 'web-php-include', title: 'File include from request data', severity: 'critical', category: 'injection', cwe: 98,
    langs: PHP, pattern: /\b(?:include|require)(?:_once)?\s*\(?\s*[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)/g,
    message: 'Including a file chosen by the user allows remote code execution.',
    remediation: 'Map user choices to an allow-list of files.',
  },
  {
    id: 'web-dynamic-require', title: 'require() from request data', severity: 'critical', category: 'injection', cwe: 94,
    langs: JS, pattern: /\brequire\s*\(\s*req\.(?:query|params|body)/g,
    message: 'Loading a module named by the user enables arbitrary code loading.',
    remediation: 'Use a static allow-list of modules.',
  },
  {
    id: 'web-open-redirect', title: 'Open redirect', severity: 'medium', category: 'injection', cwe: 601,
    langs: JS, pattern: /\bres\.redirect\s*\(\s*(?:[^)\n,]*,\s*)?req\.(?:query|params|body)\b/g,
    message: 'Redirect target is controlled by the request.',
    remediation: 'Validate the destination against an allow-list of paths or hosts.',
  },
  {
    id: 'web-open-redirect-py', title: 'Open redirect', severity: 'medium', category: 'injection', cwe: 601,
    langs: PY, pattern: /\bredirect\s*\(\s*request\.(?:args|form|values)/g,
    message: 'Redirect target is controlled by the request.',
    remediation: 'Validate with url_has_allowed_host_and_scheme or an allow-list.',
  },
  {
    id: 'web-ssrf', title: 'Server-side request forgery', severity: 'medium', category: 'injection', cwe: 918,
    langs: JS, pattern: /\b(?:axios(?:\.\w+)?|fetch|got(?:\.\w+)?|request|needle\.\w+)\s*\(\s*req\.(?:query|params|body)\b/g,
    message: 'An outbound request URL is taken from user input.',
    remediation: 'Allow-list hosts and block internal address ranges.',
  },
  {
    id: 'web-cors-wildcard', title: 'CORS allows any origin', severity: 'medium', category: 'config', cwe: 942,
    pattern: /Access-Control-Allow-Origin['"]?\s*[:,)]\s*['"]\*['"]|\bcors\s*\(\s*\{[^})]*origin\s*:\s*(['"])\*\1|\borigins?\s*=\s*['"]\*['"]/g,
    message: 'A wildcard CORS policy lets any website read responses.',
    remediation: 'List the exact trusted origins.',
    langs: [...JS, ...PY, ...PHP, ...JAVA, ...CS, ...GO, ...RB],
  },
  {
    id: 'web-cookie-httponly', title: 'Cookie without HttpOnly', severity: 'medium', category: 'config', cwe: 1004,
    langs: [...JS, ...PY], pattern: /\bhttpOnly\s*:\s*false\b|\bSESSION_COOKIE_HTTPONLY\s*=\s*False\b/g,
    message: 'JavaScript can read this cookie, aiding session theft.',
    remediation: 'Set HttpOnly to true.',
    fix: { title: 'Set HttpOnly to true', apply: (m) => m[0].replace(/false/i, (x) => (x === 'False' ? 'True' : 'true')) },
  },
  {
    id: 'web-cookie-secure', title: 'Cookie without Secure flag', severity: 'medium', category: 'config', cwe: 614,
    langs: [...JS, ...PY], pattern: /\bsecure\s*:\s*false\b|\bSESSION_COOKIE_SECURE\s*=\s*False\b/g,
    message: 'The cookie may be sent over plain HTTP.',
    remediation: 'Set Secure to true.',
    fix: { title: 'Set Secure to true', apply: (m) => m[0].replace(/false/i, (x) => (x === 'False' ? 'True' : 'true')) },
  },
  {
    id: 'web-flask-debug', title: 'Flask debug mode enabled', severity: 'high', category: 'config', cwe: 489,
    langs: PY, pattern: /\bapp\.run\s*\([^)\n]*\bdebug\s*=\s*True/g,
    message: 'The Werkzeug debugger allows remote code execution if exposed.',
    remediation: 'Never enable debug in production; read it from configuration.',
    fix: { title: 'Set debug=False', apply: (m) => m[0].replace(/debug\s*=\s*True/, 'debug=False') },
  },
  {
    id: 'web-django-debug', title: 'Django DEBUG = True', severity: 'medium', category: 'config', cwe: 489,
    langs: PY, pattern: /^\s*DEBUG\s*=\s*True\b/gm,
    message: 'Debug pages leak settings and stack traces.',
    remediation: 'Turn DEBUG off for production deployments.',
  },

  /* ─────────────── Cryptography & TLS ─────────────── */
  {
    id: 'crypto-weak-hash-node', title: 'Weak hash (MD5/SHA-1)', severity: 'medium', category: 'crypto', cwe: 327,
    langs: JS, pattern: /\bcreateHash\s*\(\s*(['"])(?:md5|sha1|md4)\1\s*\)/gi,
    message: 'MD5 and SHA-1 are broken for security purposes.',
    remediation: 'Use SHA-256 or stronger (and bcrypt/argon2 for passwords).',
    fix: { title: 'Use sha256', apply: (m) => m[0].replace(/md5|sha1|md4/i, 'sha256') },
  },
  {
    id: 'crypto-weak-hash-python', title: 'Weak hash (MD5/SHA-1)', severity: 'medium', category: 'crypto', cwe: 327,
    langs: PY, pattern: /\bhashlib\.(?:md5|sha1)\s*\(/g,
    message: 'MD5 and SHA-1 are broken for security purposes.',
    remediation: 'Use hashlib.sha256 or a password hasher such as argon2.',
    fix: { title: 'Use sha256', apply: (m) => m[0].replace(/md5|sha1/, 'sha256') },
  },
  {
    id: 'crypto-weak-hash-php', title: 'Weak hash (md5/sha1)', severity: 'medium', category: 'crypto', cwe: 327,
    langs: PHP, pattern: /(?<![\w>:$.])(?:md5|sha1)\s*\(\s*\$/g,
    message: 'md5()/sha1() must not be used for passwords or integrity.',
    remediation: 'Use password_hash() or hash("sha256", ...).',
  },
  {
    id: 'crypto-weak-hash-java', title: 'Weak digest algorithm', severity: 'medium', category: 'crypto', cwe: 327,
    langs: JAVA, pattern: /MessageDigest\.getInstance\s*\(\s*"(?:MD5|MD2|SHA-?1)"/gi,
    message: 'MD5/SHA-1 are cryptographically broken.',
    remediation: 'Use SHA-256 or SHA-3.',
  },
  {
    id: 'crypto-weak-hash-dotnet', title: 'Weak hash (MD5/SHA1)', severity: 'medium', category: 'crypto', cwe: 327,
    langs: CS, pattern: /\b(?:MD5|SHA1)(?:CryptoServiceProvider)?\.Create\s*\(|\bnew\s+(?:MD5|SHA1)CryptoServiceProvider\b/g,
    message: 'MD5/SHA1 are cryptographically broken.',
    remediation: 'Use SHA256.Create() or stronger.',
  },
  {
    id: 'crypto-weak-hash-go', title: 'Weak hash (md5/sha1)', severity: 'medium', category: 'crypto', cwe: 327,
    langs: GO, pattern: /\b(?:md5|sha1)\.(?:New|Sum)\s*\(/g,
    message: 'MD5/SHA-1 are cryptographically broken.',
    remediation: 'Use crypto/sha256.',
  },
  {
    id: 'crypto-weak-cipher', title: 'Weak cipher or ECB mode', severity: 'high', category: 'crypto', cwe: 327,
    langs: [...JS, ...PY, ...JAVA],
    pattern: /\bcreateCipher(?:iv)?\s*\(\s*(['"])[^'"]*(?:ecb|des(?!c)|rc4|rc2|blowfish)[^'"]*\1|\bMODE_ECB\b|\b(?:DES|DES3|ARC4|ARC2|Blowfish)\.new\s*\(|Cipher\.getInstance\s*\(\s*"(?:DES|DESede|RC4|AES|[^"]*\/ECB\/[^"]*)"/gi,
    message: 'Weak algorithm or ECB mode leaks plaintext patterns.',
    remediation: 'Use AES-256-GCM or ChaCha20-Poly1305 with a unique nonce.',
  },
  {
    id: 'crypto-insecure-random', title: 'Insecure randomness for secrets', severity: 'medium', category: 'crypto', cwe: 338,
    langs: [...JS, ...PY],
    pattern: /\bMath\.random\s*\(\s*\)|\brandom\.(?:random|randint|choice|randrange|choices)\s*\(/g,
    message: 'Non-cryptographic random numbers are predictable.',
    remediation: 'Use crypto.randomBytes / crypto.randomUUID or Python\'s secrets module.',
    filter: ({ lineText }) => /token|secret|passw|api_?key|nonce|session|salt|otp|csrf|auth/i.test(lineText),
  },
  {
    id: 'tls-reject-unauthorized', title: 'TLS verification disabled', severity: 'high', category: 'crypto', cwe: 295,
    langs: JS, pattern: /\brejectUnauthorized\s*:\s*false\b|\bstrictSSL\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/g,
    message: 'Certificates are not validated, enabling man-in-the-middle attacks.',
    remediation: 'Remove the override and trust a proper CA bundle.',
    fix: {
      title: 'Enable verification',
      when: ({ m }) => /false/.test(m[0]),
      apply: (m) => m[0].replace('false', 'true'),
    },
  },
  {
    id: 'tls-python-verify-false', title: 'TLS verification disabled', severity: 'high', category: 'crypto', cwe: 295,
    langs: PY, pattern: /\bverify\s*=\s*False\b/g,
    message: 'requests/httpx will accept any certificate.',
    remediation: 'Remove verify=False or point verify= at a CA bundle.',
    fix: { title: 'Set verify=True', apply: () => 'verify=True' },
  },
  {
    id: 'tls-go-skip-verify', title: 'TLS verification disabled', severity: 'high', category: 'crypto', cwe: 295,
    langs: GO, pattern: /\bInsecureSkipVerify\s*:\s*true\b/g,
    message: 'The TLS client skips certificate checks.',
    remediation: 'Remove InsecureSkipVerify.',
    fix: { title: 'Set InsecureSkipVerify: false', apply: () => 'InsecureSkipVerify: false' },
  },
  {
    id: 'tls-dotnet-callback', title: 'Certificate validation bypassed', severity: 'high', category: 'crypto', cwe: 295,
    langs: CS, pattern: /ServerCertificateValidationCallback[^\n]*=>\s*true/g,
    message: 'All certificates are accepted.',
    remediation: 'Remove the callback or validate the chain properly.',
  },
  {
    id: 'tls-paramiko-autoadd', title: 'SSH host keys auto-accepted', severity: 'medium', category: 'crypto', cwe: 295,
    langs: PY, pattern: /\bAutoAddPolicy\s*\(/g,
    message: 'Unknown SSH host keys are trusted blindly.',
    remediation: 'Use RejectPolicy and load known_hosts.',
  },
  {
    id: 'tls-curl-insecure', title: 'curl with TLS checks off', severity: 'medium', category: 'crypto', cwe: 295,
    langs: SH, pattern: /\bcurl\b[^\n|;]*\s(?:-k|--insecure)\b/g,
    message: 'curl will accept invalid certificates.',
    remediation: 'Remove -k/--insecure and fix the certificate chain.',
  },
  {
    id: 'auth-jwt-none', title: 'JWT "none" algorithm accepted', severity: 'critical', category: 'auth', cwe: 347,
    langs: [...JS, ...PY], pattern: /\balgorithms?\s*[:=]\s*\[?\s*['"]none['"]/gi,
    message: 'Unsigned tokens would be accepted as valid.',
    remediation: 'Pin a strong algorithm such as HS256/RS256 explicitly.',
  },
  {
    id: 'auth-jwt-no-expiry', title: 'JWT expiry check disabled', severity: 'medium', category: 'auth', cwe: 613,
    langs: JS, pattern: /\bignoreExpiration\s*:\s*true\b/g,
    message: 'Expired tokens remain valid.',
    remediation: 'Remove ignoreExpiration.',
    fix: { title: 'Set ignoreExpiration: false', apply: () => 'ignoreExpiration: false' },
  },

  /* ─────────────── Misc configuration ─────────────── */
  {
    id: 'net-insecure-http', title: 'Insecure http:// URL', severity: 'low', category: 'network', cwe: 319,
    pattern: /['"]http:\/\/(?!(?:localhost|127\.|0\.0\.0\.0|\[::1\]|[\w.-]*example\.|[\w.-]*\.?w3\.org|schemas\.|json-schema\.org|purl\.org|java\.sun\.com|maven\.apache\.org|ns\.adobe\.com|xmlns))[\w.-]+/gi,
    message: 'Traffic over plain HTTP can be read or modified in transit.',
    remediation: 'Use https:// endpoints.',
    langs: [...JS, ...PY, ...PHP, ...JAVA, ...CS, ...GO, ...RB, 'yaml', 'json', 'properties'],
    fix: { title: 'Use https://', apply: (m) => m[0].replace('http://', 'https://') },
  },
  {
    id: 'perm-chmod-777', title: 'World-writable permissions', severity: 'medium', category: 'config', cwe: 732,
    langs: [...SH, ...PY, ...JS, ...RB, ...PHP],
    pattern: /\bchmod\s+(?:-R\s+)?0?777\b|\bchmod\s*\([^)\n]*0o?777/g,
    message: 'Everyone can read, write and execute.',
    remediation: 'Grant the least privilege required (e.g. 755 or 644).',
  },
  {
    id: 'supply-pipe-to-shell', title: 'Remote script piped to shell', severity: 'medium', category: 'supply-chain', cwe: 494,
    langs: SH, pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/g,
    message: 'Executing unverified remote code at build time.',
    remediation: 'Download, verify a checksum or signature, then run.',
  },
  {
    id: 'py-tempfile-mktemp', title: 'tempfile.mktemp()', severity: 'medium', category: 'config', cwe: 377,
    langs: PY, pattern: /\btempfile\.mktemp\s*\(/g,
    message: 'mktemp is racy and allows symlink attacks.',
    remediation: 'Use tempfile.mkstemp() or NamedTemporaryFile().',
  },
];

const byId = new Map(RULES.map((r) => [r.id, r]));
const getRule = (id) => byId.get(id);

module.exports = { RULES, getRule, isPlaceholder, entropy, JS, PY };
