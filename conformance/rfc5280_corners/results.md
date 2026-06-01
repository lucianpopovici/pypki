# RFC 5280 Corner-Case Results

Last run: 2026-06-01T08:09:15.298421+00:00

Failures: 0

| Case | Result |
| ---- | ------ |
| aki_mismatch | PASS |
| ca_missing_basic_constraints | PASS |
| eku_client_auth | PASS |
| eku_multiple | PASS |
| expired_cert | PASS |
| intermediate_no_pathlength | PASS |
| invalid_signature | PASS |
| keyusage_digital_signature_only | PASS |
| leaf_claims_ca_true | PASS |
| minimum_validity_60s | PASS |
| name_constraints_excluded_dns | PASS |
| name_constraints_ip_address | PASS |
| name_constraints_permitted_dns | PASS |
| name_constraints_permitted_match | PASS |
| not_yet_valid | PASS |
| notbefore_after_notafter | PASS |
| pathlength_0_three_level | PASS |
| pathlength_0_two_level | PASS |
| pathlength_1_three_level_valid | PASS |
| san_rfc822name | PASS |
| san_uri | PASS |
| san_wildcard_dns | PASS |
| self_signed_not_trusted | PASS |
| serial_large_158_bits | PASS |
| ski_absent_leaf | PASS |
| unknown_critical_extension | PASS |
| unknown_noncritical_extension | PASS |
| valid_multiple_sans | PASS |
| valid_serial_one | PASS |
| validity_exactly_60s | PASS |
| validity_year_2050 | PASS |
