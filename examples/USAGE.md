# GitAntivirus Usage Examples

## Example 1: Basic Scan

Run a basic security scan on a repository:

```bash
node index.js /path/to/your/repo
```

## Example 2: Scan with Auto-Fix

```bash
node index.js /path/to/your/repo --fix
```

## Example 3: Using as a Module

```javascript
const GitAntivirus = require('./index');

const scanner = new GitAntivirus({
  scanSecrets: true,
  scanFiles: true,
  scanPackages: true,
  scanCode: true,
  autoFix: false
});

scanner.scanRepository('/path/to/repo')
  .then(results => {
    console.log(`Found ${results.stats.total} issues`);
    console.log(`Critical: ${results.stats.critical}`);
  });
```

## Example 4: GitHub Actions Integration

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run GitAntivirus
        run: npx gitantivirus scan
```

See full documentation in README.md
