# Security Policy

## Supported version

This is an educational demonstration rather than a production package. Only
the latest commit on the default branch is maintained.

## Expected finding

The missing owner check in `VulnerableToolExecutor` is intentional and is
covered by the `intentional_vulnerability` test marker. Reports describing
only that behavior will be closed as expected lab behavior.

## Reporting an unintended vulnerability

Please use this repository's **Report a vulnerability** button under GitHub's
Security tab when private vulnerability reporting is enabled. Include:

- The affected file and revision
- Reproduction steps using synthetic data
- Security impact
- A suggested mitigation, if available

If private reporting is unavailable, open a minimal issue asking the maintainer
for a private contact channel. Do not publish working credentials, private
data, or exploit details affecting a third party in a public issue.

Examples of unintended issues include credential exposure, disabled transport
security, CI privilege escalation, unsafe handling outside the documented lab
boundary, or a bypass in the protected path.

## Disclosure expectations

Allow maintainers reasonable time to reproduce and correct an unintended issue
before public disclosure. Never test against systems or data you do not own or
have explicit permission to assess.
