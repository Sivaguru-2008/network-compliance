# Pre-Refactor Baseline

This document records the exact state of the compliance engine before the Pre-Palo-Alto Architecture Refactoring.

## 1. Test Count
Running `pytest` on the test suite:
- **Total passing tests**: 957 passed (5 warnings in 64.58s)
- **Status**: All tests passing, 0 failures.

## 2. FortiGate Control Results
From running `demo_cis_fortigate.py` (assessing the sample configuration `samples/fortios_fgt.conf`):
- **Total CIS controls**: 56
- **PASS**: 3
- **FAIL**: 9
- **NEEDS_REVIEW**: 8
- **UNSUPPORTED**: 12
- **MANUAL_REVIEW**: 24
- **NOT_APPLICABLE**: 0
- **Compliance Score (evaluable only)**: 15.0%
- **Adjudicated Score (PASS vs FAIL)**: 25.0%

### Detailed Control Output:
- **FAIL (9)**:
  - `2.1.1`: Ensure 'Pre-Login Banner' is set
  - `2.1.2`: Ensure 'Post-Login-Banner' is set
  - `2.2.1`: Ensure 'Password Policy' is enabled
  - `2.2.2`: Ensure administrator password retries and lockout time
  - `2.3.1`: Ensure only SNMPv3 is enabled
  - `2.4.2`: Ensure all the login accounts having specific trusted hosts
  - `2.4.4`: Ensure idle timeout time is configured
  - `2.4.5`: Ensure only encrypted access channels are enabled
  - `2.4.7`: Ensure default Admin ports are changed
- **NEEDS_REVIEW (8)**:
  - `1.1`: Ensure DNS server is configured
  - `2.1.10`: Ensure management GUI listens on secure TLS version
  - `2.1.11`: Ensure CDN is enabled for improved GUI performance
  - `2.1.12`: Ensure single CPU core overloaded event is logged
  - `2.1.4`: Ensure correct system time is configured through NTP
  - `2.1.7`: Disable USB Firmware and configuration installation
  - `2.1.8`: Disable static keys for TLS
  - `2.1.9`: Enable Global Strong Encryption
- **PASS (3)**:
  - `2.1.5`: Ensure hostname is set
  - `7.1.1`: Enable Event Logging
  - `7.3.1`: Centralized Logging and Reporting
- **UNSUPPORTED (12)**:
  - `2.5.1`, `2.5.2`, `3.2`, `4.2.1`, `4.2.3`, `4.2.4`, `4.2.5`, `4.3.1`, `4.4.2`, `5.1.1`, `5.2.1.1`, `7.2.1`
- **MANUAL_REVIEW (24)**:
  - `1.2`, `1.3`, `2.1.3`, `2.1.6`, `2.3.2`, `2.4.1`, `2.4.3`, `2.4.6`, `2.4.8`, `2.5.3`, `3.1`, `3.3`, `3.4`, `4.1.1`, `4.1.2`, `4.2.2`, `4.2.6`, `4.3.2`, `4.3.3`, `4.4.1`, `4.4.3`, `4.4.4`, `6.1.1`, `6.1.2`

## 3. Model Fields
The fields in `SecurityBaselineModel.observable_fields()`:
1. `hostname`
2. `telnet_enabled`
3. `vty_transport_input`
4. `vty_exec_timeout_seconds`
5. `ssh_enabled`
6. `ssh_version`
7. `http_server_enabled`
8. `https_server_enabled`
9. `management_acl_applied`
10. `login_banner_present`
11. `enable_secret_set`
12. `enable_password_present`
13. `password_encryption`
14. `password_min_length`
15. `aaa_enabled`
16. `snmp_communities`
17. `logging_enabled`
18. `logging_hosts`
19. `logging_buffered`
20. `ntp_servers`
21. `dns_servers`
22. `usb_auto_install_disabled`
23. `ssl_static_key_ciphers_disabled`
24. `strong_crypto_enabled`
25. `admin_tls13_only`
26. `gui_cdn_enabled`
27. `log_single_cpu_high_enabled`
28. `admin_lockout_threshold`
29. `admin_lockout_duration`
30. `admin_default_ports_changed`
31. `pre_login_banner_present`
32. `post_login_banner_present`
33. `snmp_agent_enabled`
34. `snmp_v3_users_present`
35. `event_logging_enabled`

## 4. Mapping Count and Rule IDs
- **Mapping Count**: 56 mappings defined in `FORTIGATE_RULE_MAP`
- **Rule IDs**:
  `1.1`, `1.2`, `1.3`, `2.1.1`, `2.1.2`, `2.1.3`, `2.1.4`, `2.1.5`, `2.1.6`, `2.1.7`, `2.1.8`, `2.1.9`, `2.1.10`, `2.1.11`, `2.1.12`, `2.2.1`, `2.2.2`, `2.3.1`, `2.3.2`, `2.4.1`, `2.4.2`, `2.4.3`, `2.4.4`, `2.4.5`, `2.4.6`, `2.4.7`, `2.4.8`, `2.5.1`, `2.5.2`, `2.5.3`, `3.1`, `3.2`, `3.3`, `3.4`, `4.1.1`, `4.1.2`, `4.2.1`, `4.2.2`, `4.2.3`, `4.2.4`, `4.2.5`, `4.2.6`, `4.3.1`, `4.3.2`, `4.3.3`, `4.4.1`, `4.4.2`, `4.4.3`, `4.4.4`, `5.1.1`, `5.2.1.1`, `6.1.1`, `6.1.2`, `7.1.1`, `7.2.1`, `7.3.1`

## 5. Database State
- **Database Path**: `auditor/rules/knowledge.db`
- **Total records in `controls` table**: 355
- **Total records in `sources` table**: 11

## 6. Current Git Status
```text
On branch main
Your branch is up to date with 'origin/main'.

Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
	new file:   .claude/launch.json
	new file:   auditor/cis/__init__.py
	new file:   auditor/cis/extractor.py
	new file:   auditor/cis/fortigate_map.py
	new file:   auditor/cis/loader.py
	new file:   auditor/cis/populate_kb.py
	new file:   auditor/cis/schema.py
	modified:   auditor/engine/evaluator.py
	modified:   auditor/models/baseline.py
	modified:   auditor/models/result.py
	modified:   auditor/parsers/arista_eos.py
	modified:   auditor/parsers/cisco_ios.py
	modified:   auditor/parsers/fortios.py
	modified:   auditor/parsers/junos.py
	modified:   auditor/parsers/llm/client.py
	modified:   auditor/parsers/llm/parser.py
	modified:   auditor/parsers/llm/schema.py
	modified:   auditor/parsers/sonic.py
	modified:   auditor/pipeline.py
	modified:   auditor/report/pdf.py
	modified:   auditor/rules/frameworks/cis.json
	new file:   cis/benchmarks/CIS_Arista_EOS_benchmark_v1.0.0.pdf
	new file:   cis/benchmarks/CIS_Check_Point_Firewall_Benchmark_v1.1.0 (1).pdf
	new file:   cis/benchmarks/CIS_Cisco_Firepower_Threat_Defense_Benchmark_v1.0.0.pdf
	new file:   cis/benchmarks/CIS_Fortigate_7.0.x_Benchmark_v1.4.0.pdf
	new file:   cis/benchmarks/CIS_Fortigate_7.0.x_rules.json
	new file:   cis/benchmarks/CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf
	new file:   cis/benchmarks/CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0.pdf
	new file:   cis/benchmarks/manifest.json
	new file:   demo_cis_fortigate.py
	modified:   tests/llm_stub.py
	new file:   tests/test_adversarial_fortigate.py
	new file:   tests/test_cis_fortigate.py
	modified:   tests/test_hybrid_parser.py
	modified:   tests/test_parser_contract.py
	modified:   tests/test_parser_fortios.py
	modified:   tests/test_parser_junos.py
	modified:   tests/test_pdf_report.py
	modified:   tests/test_training.py

Untracked files:
  (use "git add <file>..." to include in what will be committed)
	tests/test_fortigate_production_readiness.py
```
