# Changelog

This document provides a high-level view of the changes to the macOS Security Compliance Project.

## [iOS 18, Revision 2.0] - 2026-07-01
* Rules
  * Added Rules
    * os_default_browser_modification_disable.yaml
    * os_default_calling_modification_disable.yaml
    * os_default_messaging_modification_disable.yaml
    * os_mail_smart_reply_disable.yaml
    * os_notes_transcription_disable.yaml
    * os_notes_transcription_summary_disable.yaml
    * os_safari_reader_summary_disable.yaml
    * os_visual_intelligence_summary.yaml
  * Modified Rules
    * icloud_sync_disable.yaml
    * icloud_drive_disable.yaml
    * os_call_recording_disable.yaml
    * os_iphone_mirroring_disable.yaml
    * os_update_enforced_software_update_delay.yaml
  * Scripts
    * generate_guidance
      * bug fixes
    * generate_scap
      * bug fixes

## [iOS 18, Revision 1.1] - 2024-12-16
* Rules
  * Added Rules
    * os_airplay_incoming_password_require
    * os_airplay_outgoing_password_require
    * os_call_recording_disable
    * os_esim_delete.yaml
    * os_external_intelligence_integration_disable
    * os_external_intelligence_integration_sign_in_disable
    * os_image_wand_disable
    * os_iphone_widgets_on_mac_disable
    * os_mail_summary_disable

  * Modified Rules
    * os_application_allow_list
    * os_install_configuration_profile_disable
    * os_marketplace_prevent
    * os_web_distribution_app_installation_disable
    * pwpolicy_history_enforce
    * pwpolicy_max_grace_period_enforce

  * Removed Rules
    * os_airplay_password_require

* Baselines
    * Added DISA STIG v1r1
    * Added INDIGO
    * Added CIS

== [iOS 18, Revision 1.0] - 2024-09-12
* Rules
  * Modified Rules
    * icloud_enterprisebook_sync
    * os_account_modification_disable
    * os_airprint_disable
    * os_airprint_force_trusted_TLS
    * os_application_deny_list
    * os_auto_correction_disable
    * os_auto_dim_allow
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
    * os_genmoji_disable
    * os_image_playground_disable
    * os_iphone_mirroring_disable
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
    * os_siri_assistant_diable
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
    * os_video_conferencing_remote_control_disable
    * os_web_distribution_app_installation_disable
    * os_writing_tools_disable
    * pwpolicy_alpha_numeric_enforce
    * pwpolicy_history_enforce

* Baselines
  * Updated Baselines

* Scripts
