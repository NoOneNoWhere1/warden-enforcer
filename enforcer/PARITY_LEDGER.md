# Parity Ledger — Rust → Go test identity mapping

**Rust baseline (main @ 385098b, CI run 2026-07-02 — all green):**
111 unit + 4 conformance tests; linux-gate 9/9 (test_api_auth.py 2, test_nftables.py 7).
The Go port must reproduce this test set identically.

One row per Rust test function. A row is satisfied when its Go test exists
in enforcer/ (verified by scripts/verify-parity.sh — identity, not counts).
PROTECTED rows are security-relevant tests that must never be dropped or renamed
without a ledger update in the same commit.

| Rust test | Go test | Status | Protected |
|---|---|---|---|
| api::post_sessions_valid_credential_returns_201 | TestPostSessionsValidCredentialReturns201 | ported |  |
| api::post_sessions_response_body_contains_session_id | TestPostSessionsResponseBodyContainsSessionID | ported |  |
| api::post_sessions_missing_required_field_returns_422 | TestPostSessionsMissingRequiredFieldReturns422 | ported |  |
| api::post_sessions_duplicate_session_id_returns_409 | TestPostSessionsDuplicateSessionIDReturns409 | ported |  |
| api::delete_existing_session_returns_204 | TestDeleteExistingSessionReturns204 | ported |  |
| api::delete_unknown_session_returns_404 | TestDeleteUnknownSessionReturns404 | ported |  |
| api::get_events_for_existing_session_returns_200_with_array | TestGetEventsForExistingSessionReturns200WithArray | ported |  |
| api::get_events_for_unknown_session_returns_404 | TestGetEventsForUnknownSessionReturns404 | ported |  |
| api::get_active_key_returns_200 | TestGetActiveKeyReturns200 | ported |  |
| api::get_active_key_body_is_okp_jwk | TestGetActiveKeyBodyIsOKPJWK | ported |  |
| api::get_active_key_body_includes_key_id | TestGetActiveKeyBodyIncludesKeyID | ported |  |
| api::get_key_by_id_returns_200_for_active_key | TestGetKeyByIDReturns200ForActiveKey | ported |  |
| api::get_key_by_id_returns_200_for_retired_key | TestGetKeyByIDReturns200ForRetiredKey | ported |  |
| api::get_key_by_id_retired_key_body_includes_retired_at | TestGetKeyByIDRetiredKeyBodyIncludesRetiredAt | ported |  |
| api::get_key_by_id_returns_404_for_unknown_key | TestGetKeyByIDReturns404ForUnknownKey | ported |  |
| api::post_sessions_invalid_cidr_target_returns_422 | TestPostSessionsInvalidCIDRTargetReturns422 | ported |  |
| api::post_sessions_sandbox_backend_failure_returns_500 | TestPostSessionsSandboxBackendFailureReturns500 | ported |  |
| api::delete_session_sandbox_backend_failure_returns_500 | TestDeleteSessionSandboxBackendFailureReturns500 | ported |  |
| breach_event::new_event_sets_layer_to_network | TestNewEventSetsLayerToNetwork | ported |  |
| breach_event::new_event_sets_attester_to_warden_enforcer | TestNewEventSetsAttesterToWardenEnforcer | ported |  |
| breach_event::new_event_sets_token_claim_to_targets | TestNewEventSetsTokenClaimToTargets | ported |  |
| breach_event::new_event_generates_non_empty_breach_id | TestNewEventGeneratesNonEmptyBreachID | ported |  |
| breach_event::two_new_events_have_distinct_breach_ids | TestTwoNewEventsHaveDistinctBreachIDs | ported |  |
| breach_event::new_event_has_empty_signature_before_signing | TestNewEventHasEmptySignatureBeforeSigning | ported |  |
| breach_event::signing_populates_non_empty_signature | TestSigningPopulatesNonEmptySignature | ported |  |
| breach_event::signed_event_verifies_with_correct_key | TestSignedEventVerifiesWithCorrectKey | ported |  |
| breach_event::tampered_violation_fails_verification | TestTamperedViolationFailsVerification | ported |  |
| breach_event::tampered_session_id_fails_verification | TestTamperedSessionIDFailsVerification | ported |  |
| breach_event::wrong_key_fails_verification | TestWrongKeyFailsVerification | ported |  |
| breach_event::rekor_payload_excludes_violation | TestRekorPayloadExcludesViolation | ported |  |
| breach_event::rekor_payload_excludes_token_claim | TestRekorPayloadExcludesTokenClaim | ported |  |
| breach_event::rekor_payload_includes_breach_id | TestRekorPayloadIncludesBreachID | ported |  |
| breach_event::rekor_payload_includes_signature | TestRekorPayloadIncludesSignature | ported |  |
| breach_event::full_event_includes_violation | TestFullEventIncludesViolation | ported |  |
| canonical::keys_are_sorted_regardless_of_input_order | TestKeysAreSortedRegardlessOfInputOrder | ported |  |
| canonical::nested_objects_are_canonicalized_recursively | TestNestedObjectsAreCanonicalizedRecursively | ported |  |
| canonical::no_insignificant_whitespace | TestNoInsignificantWhitespace | ported |  |
| cidr::valid_ipv4_cidr_parses | TestValidIPv4CidrParses | ported |  |
| cidr::valid_ipv6_cidr_parses | TestValidIPv6CidrParses | ported |  |
| cidr::host_address_without_prefix_is_error | TestHostAddressWithoutPrefixIsError | ported |  |
| cidr::empty_string_is_error | TestEmptyStringIsError | ported |  |
| cidr::ipv4_prefix_exceeding_32_is_error | TestIPv4PrefixExceeding32IsError | ported |  |
| cidr::ipv6_prefix_exceeding_128_is_error | TestIPv6PrefixExceeding128IsError | ported |  |
| cidr::slash_only_is_error | TestSlashOnlyIsError | ported |  |
| cidr::ip_inside_cidr_is_contained | TestIPInsideCidrIsContained | ported |  |
| cidr::ip_outside_cidr_is_not_contained | TestIPOutsideCidrIsNotContained | ported |  |
| cidr::network_address_is_contained | TestNetworkAddressIsContained | ported |  |
| cidr::broadcast_address_is_contained | TestBroadcastAddressIsContained | ported |  |
| cidr::ipv6_address_not_contained_in_ipv4_cidr | TestIPv6AddressNotContainedInIPv4Cidr | ported |  |
| cidr::slash_32_contains_only_that_host | TestSlash32ContainsOnlyThatHost | ported |  |
| config::config_loads_valid_signing_key_from_env | TestConfigLoadsValidSigningKeyFromEnv | ported |  |
| config::config_default_port_is_9090 | TestConfigDefaultPortIs9090 | ported |  |
| config::config_custom_port_is_parsed | TestConfigCustomPortIsParsed | ported |  |
| config::config_default_socket_path_is_run_warden_enforcer | TestConfigDefaultSocketPathIsRunWardenEnforcer | ported |  |
| config::config_custom_socket_path_is_used | TestConfigCustomSocketPathIsUsed | ported |  |
| config::config_missing_signing_key_returns_missing_error | TestConfigMissingSigningKeyReturnsMissingError | ported |  |
| config::config_missing_key_id_returns_missing_error | TestConfigMissingKeyIDReturnsMissingError | ported |  |
| config::config_malformed_base64_key_returns_invalid_error | TestConfigMalformedBase64KeyReturnsInvalidError | ported |  |
| config::config_signing_key_wrong_length_returns_invalid_error | TestConfigSigningKeyWrongLengthReturnsInvalidError | ported |  |
| config::config_non_numeric_port_returns_invalid_error | TestConfigNonNumericPortReturnsInvalidError | ported |  |
| config::config_out_of_range_port_returns_invalid_error | TestConfigOutOfRangePortReturnsInvalidError | ported |  |
| ruleset::rendered_script_contains_ipv4_table | TestRenderedScriptContainsIPv4Table | ported |  |
| ruleset::rendered_script_contains_ipv6_table | TestRenderedScriptContainsIPv6Table | ported |  |
| ruleset::default_chain_policy_is_drop | TestDefaultChainPolicyIsDrop | ported |  |
| ruleset::table_name_is_sanitized_for_nft | TestTableNameIsSanitizedForNft | ported |  |
| ruleset::each_session_gets_a_distinct_table_name | TestEachSessionGetsADistinctTableName | ported |  |
| ruleset::cloud_metadata_ipv4_is_blocked | TestCloudMetadataIPv4IsBlocked | ported |  |
| ruleset::cloud_metadata_ipv6_is_blocked | TestCloudMetadataIPv6IsBlocked | ported |  |
| ruleset::loopback_ipv4_is_blocked | TestLoopbackIPv4IsBlocked | ported |  |
| ruleset::loopback_ipv6_is_blocked | TestLoopbackIPv6IsBlocked | ported |  |
| ruleset::link_local_ipv6_is_blocked | TestLinkLocalIPv6IsBlocked | ported |  |
| ruleset::target_cidr_appears_as_accept_rule | TestTargetCidrAppearsAsAcceptRule | ported |  |
| ruleset::ipv6_table_always_present_for_ipv4_only_targets | TestIPv6TableAlwaysPresentForIPv4OnlyTargets | ported |  |
| ruleset::unconditional_deny_precedes_accept_rules | TestUnconditionalDenyPrecedesAcceptRules | ported |  |
| ruleset::egress_filter_uses_forward_hook_not_output | TestEgressFilterUsesForwardHookNotOutput | ported |  |
| ruleset::ipv4_table_has_source_nat_masquerade | TestIPv4TableHasSourceNatMasquerade | ported |  |
| ruleset::established_related_return_traffic_is_accepted | TestEstablishedRelatedReturnTrafficIsAccepted | ported |  |
| ruleset::tables_are_replaced_atomically | TestTablesAreReplacedAtomically | ported |  |
| ruleset::delete_precedes_redefinition_for_each_family | TestDeletePrecedesRedefinitionForEachFamily | ported | PROTECTED |
| ruleset::metadata_ip_is_blocked_even_when_inside_allowed_cidr | TestMetadataIPIsBlockedEvenWhenInsideAllowedCidr | ported | PROTECTED |
| sandbox_controller::new_controller_has_zero_active_sessions | TestNewControllerHasZeroActiveSessions | ported |  |
| sandbox_controller::unknown_session_is_not_active | TestUnknownSessionIsNotActive | ported |  |
| sandbox_controller::create_sandbox_makes_session_active | TestCreateSandboxMakesSessionActive | ported |  |
| sandbox_controller::create_sandbox_increments_active_count | TestCreateSandboxIncrementsActiveCount | ported |  |
| sandbox_controller::create_sandbox_duplicate_returns_already_exists | TestCreateSandboxDuplicateReturnsAlreadyExists | ported |  |
| sandbox_controller::destroy_sandbox_removes_session | TestDestroySandboxRemovesSession | ported |  |
| sandbox_controller::destroy_sandbox_decrements_active_count | TestDestroySandboxDecrementsActiveCount | ported |  |
| sandbox_controller::destroy_unknown_session_returns_not_found | TestDestroyUnknownSessionReturnsNotFound | ported |  |
| sandbox_controller::multiple_sessions_are_tracked_independently | TestMultipleSessionsAreTrackedIndependently | ported |  |
| sandbox_controller::backend_error_on_create_is_propagated | TestBackendErrorOnCreateIsPropagated | ported |  |
| sandbox_controller::backend_error_on_create_does_not_mark_session_active | TestBackendErrorOnCreateDoesNotMarkSessionActive | ported |  |
| sandbox_controller::backend_error_on_destroy_is_propagated | TestBackendErrorOnDestroyIsPropagated | ported | PROTECTED |
| seccomp::default_profile_default_action_is_allow | TestDefaultProfileDefaultActionIsAllow | ported |  |
| seccomp::default_profile_denies_ptrace | TestDefaultProfileDeniesPtrace | ported |  |
| seccomp::default_profile_denies_mount | TestDefaultProfileDeniesMount | ported |  |
| seccomp::default_profile_denies_unshare | TestDefaultProfileDeniesUnshare | ported |  |
| seccomp::default_profile_denies_setns | TestDefaultProfileDeniesSetns | ported |  |
| seccomp::default_profile_has_socket_raw_rule_with_arg_constraint | TestDefaultProfileHasSocketRawRuleWithArgConstraint | ported |  |
| seccomp::all_deny_rules_use_errno_not_kill | TestAllDenyRulesUseErrnoNotKill | ported |  |
| seccomp::profile_serializes_to_valid_json | TestProfileSerializesToValidJSON | ported |  |
| seccomp::serialized_profile_has_non_empty_syscalls_array | TestSerializedProfileHasNonEmptySyscallsArray | ported |  |
| signing_key::generated_key_has_non_empty_key_id | TestGeneratedKeyHasNonEmptyKeyID | ported |  |
| signing_key::two_generated_keys_have_distinct_key_ids | TestTwoGeneratedKeysHaveDistinctKeyIDs | ported |  |
| signing_key::two_generated_keys_have_distinct_public_keys | TestTwoGeneratedKeysHaveDistinctPublicKeys | ported |  |
| signing_key::new_key_is_not_retired | TestNewKeyIsNotRetired | ported |  |
| signing_key::retiring_key_sets_retired_at | TestRetiringKeySetsRetiredAt | ported |  |
| signing_key::private_key_bytes_roundtrip_preserves_public_key | TestPrivateKeyBytesRoundtripPreservesPublicKey | ported |  |
| signing_key::key_id_preserved_through_byte_roundtrip | TestKeyIDPreservedThroughByteRoundtrip | ported |  |
| signing_key::jwk_kty_is_okp | TestJWKKtyIsOKP | ported |  |
| signing_key::jwk_crv_is_ed25519 | TestJWKCrvIsEd25519 | ported |  |
| signing_key::jwk_x_decodes_to_matching_public_key_bytes | TestJWKXDecodesToMatchingPublicKeyBytes | ported |  |
| conformance::canonical_json_matches_frozen_vector | TestCanonicalJSONMatchesFrozenVector | ported |  |
| conformance::signature_matches_frozen_vector | TestSignatureMatchesFrozenVector | ported |  |
| conformance::frozen_public_key_matches_seed | TestFrozenPublicKeyMatchesSeed | ported |  |
| conformance::frozen_signature_verifies_against_frozen_event | TestFrozenSignatureVerifiesAgainstFrozenEvent | ported |  |
