# Microsoft Defender Local CLI Fixtures

This directory holds fixture samples for the `Microsoft Defender via local CLI` integration.

Captured files:

- `status_healthy.txt`
- `scan_clean_mpcmdrun.txt`
- `scan_detected_eicar_mpcmdrun.txt`

Planned files:

- `status_access_denied.txt`
- `status_disabled.txt`
- `status_signature_outdated.txt`
- `scan_clean_start_mpscan.txt`
- `scan_detected_eicar_start_mpscan.txt`
- `scan_detected_eicar_postscan_status.txt`
- `scan_ambiguous_success.txt`
- `scan_access_denied.txt`
- `scan_timeout.txt`
- `scan_command_not_found.txt`
- `scan_malformed_output.txt`

Fixture collection rules:

- Keep the original command output format whenever possible.
- Redact hostnames, usernames, and non-test sample paths where needed.
- Preserve return codes and threat names.
- Document the exact command used to capture each fixture.

See:

- `docs/integrations/microsoft_defender_fixture_plan.md`
- `docs/integrations/microsoft_defender_health_check_design.md`
- `docs/integrations/microsoft_defender_local_cli.md`
