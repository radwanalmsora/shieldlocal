# Contributing

1. `npm install` then `npm test` (uses the built-in Node test runner).
2. Add a rule in `src/rules.js` (`id`, `severity`, `category`, `cwe`, `langs`, global `pattern`, `message`, `remediation`, optional `filter` / `fix`).
3. Add a positive **and** a negative (false-positive) case in `test/scanner.test.js`.
4. Build secret-shaped fixtures by string concatenation so push-protection never sees a literal token.
5. `python3 scripts/make_images.py` regenerates the artwork from real scanner output.
