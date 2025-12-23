# Changelog

This document provides a high-level view of the changes to the macOS Security Compliance Project.

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