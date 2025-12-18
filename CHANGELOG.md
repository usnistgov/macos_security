# Changelog

This document provides a high-level view of the changes to the macOS Security Compliance Project.

## [Sequoia, Revision 4.0] - 2025-12-18
* Baselines
  * Added NLMAPGOV - Nederlandse Maatregelenset Apple Platformen Overheid (base/plus)
  * Modified existing baselines

## [Sequoia, Revision 3.0] - 2025-09-11
* Rules
  * Modified Rules
    * auth_smartcard_certificate_trust_enforce_high
    * os_authenticated_root_enable
    * os_ess_installed
    * os_external_storage_access_defined
    * os_home_folders_secure
    * os_iphone_mirroring_disable
    * os_network_storage_restriction
    * os_recovery_lock_enable
    * os_screensaver_timeout_loginwindow_enforce
    * os_secure_boot_verify
    * os_unlock_active_user_session_disable
    * os_world_writable_library_folder_configure
    * pwpolicy_account_lockout_enforce
    * pwpolicy_account_lockout_timeout_enforce
    * pwpolicy_history_enforce
    * pwpolicy_lower_case_character_enforce
    * pwpolicy_max_lifetime_enforce
    * pwpolicy_minimum_length_enforce
    * pwpolicy_minimum_lifetime_enforce
    * pwpolicy_special_character_enforce
    * pwpolicy_upper_case_character_enforce
    * supplemental_password_policy
    * system_settings_bluetooth_sharing_disable
    * system_settings_external_intelligence_disable
    * system_settings_external_intelligence_sign_in_disable
    * system_settings_filevault_enforce
    * system_settings_hot_corners_secure
    * system_settings_location_services_menu_enforce
    * system_settings_remote_management_disable
    * system_settings_time_machine_encrypted_configure
  * Bug Fixes
* Baselines
  * Modified existing baselines
* Scripts
  * generate_baseline
    * Updated regex
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

## [Sequoia, Revision 2.0] - 2025-07-01
* Rules
  * Added Rules
    * os_mail_smart_reply_disable
    * os_notes_transcription_disable
    * os_notes_transcription_summary_disable
    * os_safari_reader_summary_disable
    * os_sshd_per_source_penalties_configure
  * Modified Rules
    * os_genmoji_disable.yaml
    * os_implement_cryptography.yaml
    * os_iphone_mirroring_disable.yaml
    * os_mail_summary_disable.yaml
    * os_nfsd_disable.yaml
    * os_parental_controls_enable.yaml
    * os_password_hint_remove.yaml
    * os_power_nap_disable.yaml
    * os_separate_functionality.yaml
    * os_sleep_and_display_sleep_apple_silicon_enable.yaml
    * os_sudo_log_enforce.yaml
    * os_time_server_enabled.yaml
    * os_unlock_active_user_session_disable
    * os_writing_tools_disable.yaml
    * pwpolicy_50_percent.yaml
    * pwpolicy_history_enforce.yaml
    * pwpolicy_upper_case_character_enforce.yaml
    * supplemental_cis_manual.yaml
    * system_settings_automatic_login_disable.yaml
    * system_settings_bluetooth_sharing_disable.yaml
    * system_settings_content_caching_disable.yaml
    * system_settings_external_intelligence_disable.yaml
    * system_settings_external_intelligence_sign_in_disable.yaml
    * system_settings_guest_access_smb_disable.yaml
    * system_settings_guest_account_disable.yaml
    * system_settings_improve_assistive_voice_disable.yaml
    * system_settings_improve_search_disable.yaml
    * system_settings_internet_sharing_disable.yaml
    * system_settings_loginwindow_loginwindowtext_enable.yaml
    * system_settings_loginwindow_prompt_username_password_enforce.yaml
    * system_settings_media_sharing_disabled.yaml
    * system_settings_password_hints_disable.yaml
    * system_settings_printer_sharing_disable.yaml
    * system_settings_rae_disable.yaml
    * system_settings_remote_management_disable.yaml
    * system_settings_screen_sharing_disable.yaml
    * system_settings_screensaver_ask_for_password_delay_enforce.yaml
    * system_settings_screensaver_timeout_enforce.yaml
    * system_settings_siri_disable.yaml
    * system_settings_siri_listen_disable.yaml
    * system_settings_smbd_disable.yaml
    * system_settings_software_update_enforce.yaml
    * system_settings_ssh_disable.yaml
    * system_settings_time_server_configure.yaml
    * system_settings_time_server_enforce.yaml
    * system_settings_wake_network_access_disable.yaml
  * Bug Fixes
* Baselines
    * Updated CIS to v1.1.0
    * Updated DISA STIG Ver 1, Rel 3
* Scripts
  * generate_guidance
    * bug fixes
  * generate_scap.py
    * bug fixes

## [Sequoia, Revision 1.1] - 2024-12-16

* Rules
  * Added Rules
    * os_iphone_mirroring_disable
    * os_mail_summary_disable
    * os_photos_enhanced_search_disable
    * system_settings_external_intelligence_disable
    * system_settings_external_intelligence_sign_in_disable
  * Modified Rules
    * os_sleep_and_display_sleep_apple_silicon_enable
    * os_sudo_log_enforce
    * os_world_writable_library_folder_configure
    * os_password_autofill_disable
    * pwpolicy_alpha_numeric_enforce
    * pwpolicy_custom_regex_enforce
    * pwpolicy_lower_case_character_enforce.yaml
    * pwpolicy_max_lifetime_enforce
    * pwpolicy_minimum_lifetime_enforce
    * pwpolicy_history_enforce
    * pwpolicy_account_lockout_timeout_enforce
    * pwpolicy_account_lockout_enforce
    * pwpolicy_prevent_dictionary_words
    * pwpolicy_simple_sequence_disable
    * pwpolicy_special_character_enforce
    * pwpolicy_upper_case_character_enforce.yaml
    * system_settings_improve_assistive_voice_disable
  * Removed Rules
    * system_settings_cd_dvd_sharing_disable
  * Bug Fixes
* Baselines
  * Added DISA STIG v1r1
  * Added CIS Level (Draft -> Final)
  * Updated CNSSI-1253

## [Sequoia, Revision 1.0] - 2024-09-12

* Rules
  * Added Rules
    * os_genmoji_disable
    * os_image_generation_disable
    * os_iphone_mirroring_disable
    * os_sudo_log_enforce
    * os_writing_tools_disable
  * Modified Rules
    * os_anti_virus_installed
    * os_gatekeeper_enable
    * os_ssh_fips_compliant
    * system_settings_firewall_enable
    * system_settings_firewall_stealth_mode_enable
    * system_settings_gatekeeper_identified_developers_allowed
    * system_settings_media_sharing_disabled
    * DDM Support
      * auth_pam_login_smartcard_enforce
      * auth_pam_su_smartcard_enforce
      * auth_pam_sudo_smartcard_enforce
      * auth_ssh_password_authentication_disable
      * os_external_storage_restriction
      * os_network_storage_restriction
      * os_policy_banner_ssh_enforce
      * os_sshd_channel_timeout_configure
      * os_sshd_client_alive_count_max_configure
      * os_sshd_client_alive_interval_configure
      * os_sshd_fips_compliant
      * os_sshd_login_grace_time_configure
      * os_sshd_permit_root_login_configure
      * os_sshd_unused_connection_timeout_configure
      * os_sudo_timeout_configure
      * pwpolicy_account_lockout_enforce
      * pwpolicy_account_lockout_timeout_enforce
      * pwpolicy_alpha_numeric_enforce
      * pwpolicy_custom_regex_enforce
      * pwpolicy_history_enforce
      * pwpolicy_max_lifetime_enforce
      * pwpolicy_minimum_length_enforce
      * pwpolicy_simple_sequence_disable
      * pwpolicy_special_character_enforce
    * Removed Rules
      * os_firewall_log_enable
      * os_gatekeeper_rearm
      * os_safari_popups_disabled
    * Bug Fixes
* Baselines
  * Modified existing baselines
  * Updated 800-171 to Revision 3
* Scripts
  * generate_guidance
    * Support for Declarative Device Management (DDM)
    * Added support for severity
  * generate_baseline
  * generate_mappings
  * generate_scap
    * Added support for severity
