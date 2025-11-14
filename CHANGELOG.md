# Changelog

This document provides a high-level view of the changes to the macOS Security Compliance Project.

## [iOS 17, Revision 4.0] - 2025-07-01
* Rules
  * bug fixes
* Scripts
  * generate_guidance
    * bug fixes
  * generate_scap
    * bug fixes



## [iOS 17, Revision 3.0] - 2024-09-12

* Rules
  * Added Rules
    * icloud_enterprisebook_sync
    * os_account_modification_disable
    * os_airprint_disable
    * os_airprint_force_trusted_TLS
    * os_application_deny_list
    * os_auto_correction_disable
    * os_chat_disable
    * os_definition_lookup_disable
    * os_device_name_change_disable
    * os_diagnostics_reports_modification_disable
    * os_exchange_mail_recents_sync_disable
    * os_exchange_peraccountVPN
    * os_exchange_prevent_move_enforce
    * os_exchange_SMIME_encryption_certificate_overwirte_disable
    * os_exchange_SMIME_encryption_default_certificate_overwrite_enable
    * os_exchange_SMIME_encryption_enforce
    * os_exchange_SMIME_encryption_per_message_disable
    * os_exchange_SMIME_signing_certificate_overwirte_disable
    * os_exchange_SMIME_signing_enabled
    * os_exchange_SMIME_signing_overwrite_disable
    * os_iphone_widgets_on_mac_disable
    * os_live_text_disable
    * os_mail_block_remote_content
    * os_marketplace_prevent
    * os_network_known_only
    * os_predictive_keyboard_disable
    * os_rapid_security_responses_install_enable
    * os_rapid_security_responses_remove_disable
    * os_safari_JavaScript_disable
    * os_safari_popups_disable
    * os_screen_observation_remote_disable
    * os_screen_observation_unprompted_disable
    * os_siri_allow_dictation_disable
    * os_siri_assistant_disable
    * os_siri_server_logging_disable
    * os_siri_user_generated_content_disable
    * os_spell_check_disable
    * os_system_settings_find_my_device_disable
    * os_system_settings_find_my_friends_modification_disable
    * os_unpaired_boot_disable
    * os_update_auto_RSR_allow
    * os_update_enforced_software_update_delay
    * os_update_force_delayed_software_updates
    * os_update_OTAPKI_allow
    * pwpolicy_alpha_numeric_enforce
    * pwpolicy_history_enforce
    * supplemental_bsi
* Baselines
  * Added Baselines
    * Indigo (Base/High)
* Scripts
  * generate_guidance
    * Updated date format for compliance script (https://github.com/usnistgov/macos_security/issues/405[#405])
    * Spelling fixes (https://github.com/usnistgov/macos_security/pull/409[#409])
    * Support `.yaml` & .`yml` (https://github.com/usnistgov/macos_security/issues/412[#412])
    * Support for Indigo
  * generate_baseline
    * Removed unnecessary try blocks (https://github.com/usnistgov/macos_security/issues/401[#401])
    * Update with correct syntax for replace (https://github.com/usnistgov/macos_security/pull/406[#406])
    * Support `.yaml` & .`yml` (https://github.com/usnistgov/macos_security/issues/412[#412])
    * Support for Indigo

## [iOS 17, Revision 2.0] - 2024-04-24

* Rules
  * Modified Rules
    * icloud_backup_disabled
    * icloud_keychain_disable
    * icloud_managed_apps_store_data_disabled
    * icloud_photos_disable
    * icloud_shared_photo_stream_disable
    * icloud_sync_disable
    * os_airdrop_disable
    * os_airdrop_unmanaged_destination_enable
    * os_airplay_password_require
    * os_allow_contacts_read_managed_sources_unmanaged_destinations_disable
    * os_allow_contacts_write_managed_sources_unmanaged_destinations_disable
    * os_allow_documents_managed_sources_unmanaged_destinations_disable
    * os_allow_documents_unmanaged_sources_managed_destinations_disable
    * os_apple_watch_pairing_disable
    * os_apple_watch_wrist_detection_enable
    * os_application_allow_list
    * os_auto_unlock_disable
    * os_diagnostics_reports_disable
    * os_disallow_enterprise_app_trust
    * os_enterprise_books_disable
    * os_files_network_drive_access_disable
    * os_files_usb_drive_access_disable
    * os_find_my_friends_disable
    * os_force_encrypted_backups_enable
    * os_handoff_disable
    * os_install_vpn_configuration_disable
    * os_iphone_widgets_on_mac_disable
    * os_limit_ad_tracking_enable
    * os_mail_maildrop_disable
    * os_mail_move_messages_disable
    * os_new_device_proximity_disable
    * os_on_device_dictation_enforce
    * os_on_device_translation_enforce
    * os_password_autofill_disable
    * os_password_proximity_disable
    * os_password_sharing_disable
    * os_require_managed_pasteboard_enforce
    * os_safari_cookies_set
    * os_safari_force_fraud_warning_enable
    * os_safari_password_autofill_disable
    * os_show_calendar_lock_screen_disable
    * os_show_notification_center_lock_screen_disable
    * os_siri_when_locked_disabled
    * os_ssl_for_exchange_activesync_enable
    * os_supervised_mdm_require
    * os_untrusted_tls_disable
    * os_usb_accessories_when_locked_disable
    * pwpolicy_account_lockout_enforce
    * pwpolicy_force_pin_enable
    * pwpolicy_max_grace_period_enforce
    * pwpolicy_max_inactivity_enforce
    * pwpolicy_minimum_length_enforce
    * pwpolicy_simple_sequence_disable
* Supplemental
    * supplemental_cis_manual
    * supplemental_stig

* Baselines
  * Added
    * ios_stig
    * ios_stig_byoad
  * Modified
    * 800-53r5_high
    * 800-53r5_low
    * 800-53r5_moderate
    * all_rules
    * cis_lvl1_byod
    * cis_lvl1_enterprise
    * cis_lvl2_byod
    * cis_lvl2_enterprise
    * cisv8

## [iOS 17, Revision 1.0] - 2023-09-21

Initial Public release
