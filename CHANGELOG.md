# Changelog

This document provides a high-level view of the changes to the macOS Security Compliance Project.
## [Tahoe, Revision 3.0] - 2026-06-XX

* Rules
  * Added Rules
    * os_external_apfs_hfs_volumes_encrypted
    * os_internal_apfs_volumes_encrypted
    * os_safari_allow_javascript_disable
    * system_settings_background_security_improvement_removal_disable
    * system_settings_macos_updates_install_enforce
  * Modified Rules
    * audit_acls_files_configure
    * audit_acls_folders_configure
    * audit_auditd_enabled
    * audit_control_acls_configure
    * audit_control_group_configure
    * audit_control_mode_configure
    * audit_control_owner_configure
    * audit_files_group_configure
    * audit_files_mode_configure
    * audit_files_owner_configure
    * audit_flags_aa_configure
    * audit_flags_ad_configure
    * audit_flags_ex_configure
    * audit_flags_fd_configure
    * audit_flags_fm_configure
    * audit_flags_fm_failed_configure
    * audit_flags_fr_configure
    * audit_flags_fw_configure
    * audit_flags_lo_configure
    * audit_folder_group_configure
    * audit_folder_owner_configure
    * audit_folders_mode_configure
    * audit_off_load_records
    * audit_retention_configure
    * auth_pam_login_smartcard_enforce
    * auth_pam_su_smartcard_enforce
    * auth_pam_sudo_smartcard_enforce
    * auth_smartcard_allow
    * auth_smartcard_certificate_trust_enforce_high
    * auth_smartcard_certificate_trust_enforce_moderate
    * auth_smartcard_enforce
    * auth_ssh_password_authentication_disable
    * icloud_addressbook_disable
    * icloud_appleid_system_settings_disable
    * icloud_bookmarks_disable
    * icloud_calendar_disable
    * icloud_drive_disable
    * icloud_freeform_disable
    * icloud_game_center_disable
    * icloud_keychain_disable
    * icloud_mail_disable
    * icloud_notes_disable
    * icloud_photos_disable
    * icloud_private_relay_disable
    * icloud_reminders_disable
    * icloud_sync_disable
    * os_access_control_mobile_devices
    * os_account_modification_disable
    * os_airdrop_disable
    * os_anti_virus_installed
    * os_auth_peripherals
    * os_authenticated_root_enable
    * os_bonjour_disable
    * os_calendar_app_disable
    * os_certificate_authority_trust
    * os_config_data_install_enforce
    * os_dictation_disable
    * os_erase_content_and_settings_disable
    * os_external_apfs_hfs_volumes_encrypted
    * os_external_storage_access_defined
    * os_facetime_app_disable
    * os_firewall_default_deny_require
    * os_firmware_password_require
    * os_gatekeeper_enable
    * os_genmoji_disable
    * os_handoff_disable
    * os_hibernate_mode_intel_enable
    * os_home_folders_default
    * os_home_folders_secure
    * os_httpd_disable
    * os_image_playground_disable
    * os_implement_cryptography
    * os_install_log_retention_configure
    * os_internal_apfs_volumes_encrypted
    * os_iphone_mirroring_disable
    * os_ir_support_disable
    * os_mail_app_disable
    * os_mail_smart_reply_disable
    * os_mail_summary_disable
    * os_malicious_code_prevention
    * os_mdm_require
    * os_messages_app_disable
    * os_nfsd_disable
    * os_nonlocal_maintenance
    * os_notes_transcription_disable
    * os_notes_transcription_summary_disable
    * os_obscure_password
    * os_on_device_dictation_enforce
    * os_password_hint_remove
    * os_password_proximity_disable
    * os_password_sharing_disable
    * os_photos_enhanced_search_disable
    * os_power_nap_disable
    * os_privacy_setup_prompt_disable
    * os_protect_dos_attacks
    * os_provide_automated_account_management
    * os_rapid_security_response_allow
    * os_rapid_security_response_removal_disable
    * os_recovery_lock_enable
    * os_root_disable
    * os_safari_advertising_privacy_protection_enable
    * os_safari_allow_javascript_disable
    * os_safari_open_safe_downloads_disable
    * os_safari_prevent_cross-site_tracking_enable
    * os_safari_reader_summary_disable
    * os_safari_show_full_website_address_enable
    * os_safari_show_status_bar_enabled
    * os_safari_warn_fraudulent_website_enable
    * os_secure_boot_verify
    * os_secure_enclave
    * os_secure_name_resolution
    * os_separate_functionality
    * os_setup_assistant_filevault_enforce
    * os_sip_enable
    * os_siri_prompt_disable
    * os_skip_apple_intelligence_enable
    * os_skip_screen_time_prompt_enable
    * os_sleep_and_display_sleep_apple_silicon_enable
    * os_software_update_app_update_enforce
    * os_ssh_fips_compliant
    * os_sshd_fips_compliant
    * os_sshd_per_source_penalties_configure
    * os_store_encrypted_passwords
    * os_sudo_log_enforce
    * os_sudo_timeout_configure
    * os_sudoers_timestamp_type_configure
    * os_system_read_only
    * os_terminal_secure_keyboard_enable
    * os_tftpd_disable
    * os_time_server_enabled
    * os_touchid_prompt_disable
    * os_unlock_active_user_session_disable
    * os_user_app_installation_prohibit
    * os_uucp_disable
    * os_verify_remote_disconnection
    * os_world_writable_library_folder_configure
    * os_writing_tools_disable
    * pwpolicy_alpha_numeric_enforce
    * pwpolicy_custom_regex_enforce
    * pwpolicy_force_password_change
    * pwpolicy_history_enforce
    * pwpolicy_lower_case_character_enforce
    * pwpolicy_max_lifetime_enforce
    * pwpolicy_minimum_length_enforce
    * pwpolicy_minimum_lifetime_enforce
    * pwpolicy_simple_sequence_disable
    * pwpolicy_special_character_enforce
    * pwpolicy_upper_case_character_enforce
    * supplemental_cis_manual
    * supplemental_filevault
    * system_settings_airplay_receiver_disable
    * system_settings_apple_watch_unlock_disable
    * system_settings_automatic_login_disable
    * system_settings_background_security_improvement_removal_disable
    * system_settings_bluetooth_disable
    * system_settings_bluetooth_settings_disable
    * system_settings_bluetooth_sharing_disable
    * system_settings_content_caching_disable
    * system_settings_critical_update_install_enforce
    * system_settings_diagnostics_reports_disable
    * system_settings_download_software_update_enforce
    * system_settings_external_intelligence_disable
    * system_settings_external_intelligence_sign_in_disable
    * system_settings_filevault_enforce
    * system_settings_find_my_disable
    * system_settings_firewall_enable
    * system_settings_firewall_stealth_mode_enable
    * system_settings_gatekeeper_identified_developers_allowed
    * system_settings_gatekeeper_override_disallow
    * system_settings_guest_access_smb_disable
    * system_settings_guest_account_disable
    * system_settings_hot_corners_secure
    * system_settings_improve_assistive_voice_disable
    * system_settings_improve_search_disable
    * system_settings_improve_siri_dictation_disable
    * system_settings_install_macos_updates_enforce
    * system_settings_internet_accounts_disable
    * system_settings_internet_sharing_disable
    * system_settings_location_services_disable
    * system_settings_loginwindow_loginwindowtext_enable
    * system_settings_macos_updates_install_enforce
    * system_settings_media_sharing_disabled
    * system_settings_password_hints_disable
    * system_settings_personalized_advertising_disable
    * system_settings_printer_sharing_disable
    * system_settings_rae_disable
    * system_settings_remote_management_disable
    * system_settings_screen_sharing_disable
    * system_settings_screensaver_ask_for_password_delay_enforce
    * system_settings_screensaver_password_enforce
    * system_settings_screensaver_timeout_enforce
    * system_settings_security_update_install
    * system_settings_siri_disable
    * system_settings_siri_settings_disable
    * system_settings_smbd_disable
    * system_settings_software_update_download_enforce
    * system_settings_softwareupdate_current
    * system_settings_ssh_disable
    * system_settings_ssh_enable
    * system_settings_system_wide_preferences_configure
    * system_settings_time_machine_encrypted_configure
    * system_settings_time_server_configure
    * system_settings_time_server_enforce
    * system_settings_touch_id_settings_disable
    * system_settings_touchid_unlock_disable
    * system_settings_wallet_applepay_settings_disable
    * system_settings_wifi_disable
    * system_settings_wifi_disable_when_connected_to_ethernet
  * Removed Rules
    * os_rapid_security_response_allow
    * os_rapid_security_response_removal_disable
* Baselines
  * Added NLMAPGOV_Base
  * Added NLMAPGOV_Plus
  * Added HICP Large Practice
  * Modified existing baselines
* Scripts
  * generate_guidance
    * Updated to support NLMAPGOV
    * Updated to support HICP LP
    * Bug Fixes  
## [Tahoe, Revision 2.0] – 2025-12-18

* Rules
  * Added Rules
    * os_loginwindow_adminhostinfo_disabled
    * os_safari_clear_history_disable
    * os_safari_private_browsing_disable
    * os_skip_apple_intelligence_enable
    * system_settings_download_software_update_enforce
    * system_settings_security_update_install
  * Modified Rules
    * audit_auditd_enabled
    * os_icloud_storage_prompt_disable
    * os_privacy_setup_prompt_disable
    * os_recovery_lock_enable
    * os_secure_boot_verify
    * os_siri_prompt_disable
    * os_skip_screen_time_prompt_enable
    * os_skip_unlock_with_watch_enable
    * os_time_server_enabled
    * os_touchid_prompt_disable
    * os_unlock_active_user_session_disable
    * pwpolicy_account_lockout_enforce
    * pwpolicy_account_lockout_timeout_enforce
    * pwpolicy_history_enforce
    * pwpolicy_lower_case_character_enforce
    * pwpolicy_upper_case_character_enforce
    * pwpolicy_special_character_enforce
    * pwpolicy_minimum_length_enforce
    * pwpolicy_minimum_lifetime_enforce
    * pwpolicy_max_lifetime_enforce
    * system_settings_location_services_enable
    * system_settings_location_services_disable
    * system_settings_screen_sharing_disable
    * system_settings_ssh_disable
    * system_settings_bluetooth_sharing_disable
    * system_settings_hot_corners_secure
    * system_settings_time_machine_encrypted_configure
  * Removed Rules
    * system_settings_software_update_enforce
  * Bug Fixes
* Baselines
  * Added STIG - Ver 1, Rel 1
  * Modified existing baselines
* Scripts
  * generate_guidance
    * Bug fixes related to consolidated configuration profile generation
    * Improved handling of Declarative Device Management (DDM) nested keys
    * Compliance script stability improvements
  * generate_scap
    * Minor fixes to SCAP/XCCDF output generation

## [Tahoe, Revision 1.0] - 2025-09-11

* Rules
  * Added Rules
    * os_loginwindow_adminhostinfo_disabled
    * os_safari_clear_history_disable
    * os_safari_private_browsing_disable
    * os_skip_apple_intelligence_enable
    * system_settings_download_software_update_enforce
    * system_settings_security_update_install
  * Modified Rules
    * audit_auditd_enabled
    * os_appleid_prompt_disable
    * os_authenticated_root_enable
    * os_external_storage_access_defined
    * os_httpd_disable
    * os_icloud_storage_prompt_disable
    * os_network_storage_restriction
    * os_privacy_setup_prompt_disable
    * os_recovery_lock_enable
    * os_screensaver_loginwindow_enforce
    * os_secure_boot_verify
    * os_siri_prompt_disable
    * os_skip_screen_time_prompt_enable
    * os_skip_unlock_with_watch_enable
    * os_tftpd_disable
    * os_time_server_enabled
    * os_touchid_prompt_disable
    * os_unlock_active_user_session_disable
    * os_world_writable_library_folder_configure
    * os_uucp_disable
    * pwpolicy_account_lockout_enforce
    * pwpolicy_account_lockout_timeout_enforce
    * pwpolicy_history_enforce
    * pwpolicy_lower_case_character_enforce
    * pwpolicy_max_lifetime_enforce
    * pwpolicy_minimum_length_enforce
    * pwpolicy_minimum_lifetime_enforce
    * pwpolicy_special_character_enforce
    * pwpolicy_upper_case_character_enforce
    * system_settings_bluetooth_sharing_disable
    * system_settings_hot_corners_secure
    * system_settings_location_services_disable
    * system_settings_location_services_enable
    * system_settings_screen_sharing_disable
    * system_settings_ssh_disable
    * system_settings_time_machine_encrypted_configure
  * Removed Rules
    * os_loginwindow_adminhostinfo_undefined
    * os_show_filename_extensions_enable
    * system_settings_security_update_install
    * system_settings_software_update_enforce
  * Bug Fixes
* Baselines
  * Modified existing baselines
* Scripts
  * generate_guidance
    * Added flag for consolidated configuration profile
    * Updated DDM logic for nested keys
    * Added shell check to compliance script
    * Updated current user check in compliance script
    * Support for Managed Arguments in compliance script
    * Bug Fixes
  * generate_scap
    * Support for oval 5.12.1
    * Support for scap 1.4
    * Added shellcommand for all tests