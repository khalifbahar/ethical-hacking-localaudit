# LocalAudit

**Local Security Misconfiguration Auditor**

## Description
LocalAudit is an original ethical auditing tool for the Auditing category. It performs local-only security checks for common misconfigurations such as overly permissive file permissions on sensitive files, world-writable directories, open local ports, and umask settings. All checks run against the local system only.

## Attack Category
Auditing

## Attack Lifecycle Mapping
- **Reconnaissance / Auditing**: Primary phase. Collects local configuration data to identify security weaknesses.
- **Scanning**: Limited local checks only (no remote scanning).
- **Exploitation**: None.
- **Reporting**: Results saved locally in JSON.

## Installation
```bash
git clone <your-repo-url>
cd localauditor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # No external deps
chmod +x localauditor.py
```

## Usage Examples
```bash
# Run full local audit (safe default)
python3 localauditor.py

# Custom output directory
python3 localauditor.py -o ./results

# Skip world-writable scan
python3 localauditor.py --skip-writable
```

## Ethical Considerations
The tool only audits the local system, requires explicit authorization confirmation, uses safe defaults, includes a kill switch (Ctrl+C), and stores results only locally.

## Rules of Engagement (RoE)
- **Authorized Scope**: Local system only (or systems for which you have explicit written authorization).
- **Time Windows**: During authorized testing windows only.
- **Permitted Techniques**: Read-only checks of file permissions, directory listings, and local port status.
- **Prohibited Actions**: No modification of system files, no remote scanning, no exploitation, no use on unauthorized systems.
- **Emergency Stop**: Press Ctrl+C to abort immediately. Delete the output directory if required.

## Responsible Disclosure
If issues are found on a system you are authorized to audit:
1. Document findings privately.
2. Report to the system owner / security team.
3. Do not publicly disclose without permission.
4. Allow reasonable time for remediation.

## Legal Disclaimer
References the Computer Crimes Act 1997 (Malaysia). Unauthorized use is illegal. See the startup banner.

## Limitation Notes
- Checks are basic and non-exhaustive.
- Some checks may require elevated privileges to see full results (e.g. /etc/shadow).
- World-writable scan is depth-limited for performance.
- Designed for educational purposes.

## License
MIT License.

## Output
Timestamped JSON report saved in the output directory (default: ./output).
