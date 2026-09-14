# Changelog

This document provides a high-level view of the changes to the macOS Security Compliance Project.
## [ mSCP 2.0, Release 27.0 ]

* Rules
  * Added Rules
    * os_bluetooth_modification_disable
    * os_chat_disable
    * os_call_recording_disable
    * system_settings_siri_AI_disable
    * os_apple_intelligence_pcc_disable
    * os_allow_enterprise_trust_disabled
    * os_apple_intelligence_pcc_disable
    * os_calendar_app_disable_familycontrols
    * os_erase_contents_and_settings_disable
    * os_facetime_app_disable_familycontrols
    * os_install_configuration_profile_disable
    * os_messages_app_disable_familycontrols
    * os_natural_language_editing_disable
    * os_visual_intelligence_disable
  * Removed Rules
    * os_auto_dim_allow
    * os_safari_popups_disabled
    * os_time_offset_limit_configure
  * Merged Rules
    * icloud_enterprisebook_sync → icloud_enterprisebook_metadata_sync_disable
    * os_airplay_password_require → os_airplay_outgoing_password_require
    * os_background_security_improvement_removal_disable → system_settings_background_security_improvement_removal_disable
    * os_config_profile_ui_install_disable → os_install_configuration_profile_disable
    * os_disallow_enterprise_app_trust → os_allow_enterprise_trust_disabled
    * os_erase_content_and_settings_disable → os_allow_enterprise_trust_disabled
    * os_exchange_prevent_move_enforce → os_mail_move_messages_disable
    * os_external_intelligence_integration_disable → system_settings_external_intelligence_sign_in_disable
    * os_external_intelligence_integration_sign_in_disable → system_settings_external_intelligence_sign_in_disable
    * os_image_generation_disable → os_image_playground_disable
    * os_siri_allow_dictation_disable → os_dictation_disable
    * os_software_update_download_enforce & system_settings_download_software_update_enforce → system_settings_software_update_download_enforce
    * os_software_update_install_enforce & system_settings_macos_updates_install_enforce → system_settings_install_macos_updates_enforce
    * system_settings_security_update_install → system_settings_critical_update_install_enforce
    * os_software_update_app_update_enforce → system_settings_software_update_app_update_enforce
  * Modified Rules
    * icloud_addressbook_disable
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
    * os_account_modification_disable
    * os_airdrop_disable
    * os_appleid_prompt_disable
    * os_bluetooth_modification_disable
    * os_calendar_app_disable
    * os_call_recording_disable
    * os_camera_disable
    * os_definition_lookup_disable
    * os_dictation_disable
    * os_erase_contents_and_settings_disable
    * os_facetime_app_disable
    * os_gatekeeper_enable
    * os_genmoji_disable
    * os_handoff_disable
    * os_icloud_storage_prompt_disable
    * os_image_playground_disable
    * os_install_configuration_profile_disable
    * os_iphone_mirroring_disable
    * os_mail_smart_reply_disable
    * os_mail_summary_disable
    * os_messages_app_disable
    * os_notes_transcription_disable
    * os_notes_transcription_summary_disable
    * os_on_device_dictation_enforce
    * os_parental_controls_enable
    * os_password_autofill_disable
    * os_password_proximity_disable
    * os_password_sharing_disable
    * os_privacy_setup_prompt_disable
    * os_rapid_security_response_allow
    * os_rapid_security_response_removal_disable
    * os_safari_clear_history_disable
    * os_safari_private_browsing_disable
    * os_safari_reader_summary_disable
    * os_screenshots_disable
    * os_siri_prompt_disable
    * os_skip_apple_intelligence_enable
    * os_skip_screen_time_prompt_enable
    * os_skip_unlock_with_watch_enable
    * os_ssh_server_alive_count_max_configure
    * os_ssh_server_alive_interval_configure
    * os_ssh_fips_compliant
    * os_touchid_prompt_disable
    * os_writing_tools_disable
    * system_settings_airplay_receiver_disable
    * system_settings_apple_watch_unlock_disable
    * system_settings_biometric_disable
    * system_settings_content_caching_disable
    * system_settings_critical_update_install_enforce
    * system_settings_diagnostics_reports_disable
    * system_settings_external_intelligence_disable
    * system_settings_external_intelligence_sign_in_disable
    * system_settings_find_my_disable
    * system_settings_gatekeeper_override_disallow
    * system_settings_improve_assistive_voice_disable
    * system_settings_improve_search_disable
    * system_settings_critical_update_install_enforce
    * system_settings_internet_sharing_disable
    * system_settings_media_sharing_disabled
    * system_settings_personalized_advertising_disable
    * system_settings_siri_disable
    * system_settings_software_update_download_enforce
    * system_settings_time_server_enforce
    * system_settings_usb_restricted_mode
* Schema
  * Rule Schema
    * Removed macOS 14 support
    * Added macOS 27 support
    * Added Ubuntu and RedHat as supported platforms
    * Rule values can now be arrays of objects
    * Added com.apple.configuration.app.settings declaration
    * Added exit code support
* Scripts
  * common_utils
    * Added Ubuntu and Red Hat to the supported Unix-like platform list.
    * Added friendly platform-name mappings for Ubuntu and Red Hat.
    * Improved YAML parsing performance by using PyYAML’s C-backed CSafeLoader when available, with fallback to SafeLoader.
    * Updated !localize handling so localization continues to work with the optimized YAML loader.
    * Reduced default logging overhead by writing INFO-level records instead of DEBUG unless debug/high verbosity is explicitly enabled.
  * classes
    * Added support for exit-code-based check results through a new exit_code result field and result_exit_code rule property.
    * Added Declarative Device Management as a recognized enforcement mechanism when ddm_info is present.
    * Improved customization merging for platform data by prioritizing the rule result during deep merges.
    * Changed enforcement handling so platform-level enforcement_info is no longer automatically merged with OS-version-specific enforcement data.
    * Expanded $ODV substitution to work inside Pydantic/BaseModel objects, not just strings, dictionaries, and lists.
    * Improved configuration profile generation so arrays can contain typed and nested values such as integers, booleans, dictionaries, and additional arrays instead of assuming every array item is a string.
    * Simplified reference processing by removing special-case handling for bzk and hhs references.
    * Updated rule metadata/documentation to recognize Declarative Device Management alongside Script, Configuration Profile, Manual, Inherent, Permanent, and N/A mechanisms.
  * generate
    * Removed the Ruby/AsciiDoctor dependency from guidance generation.
    * Replaced AsciiDoctor PDF generation with Typst.
    * Reworked HTML generation to render directly through Python/Jinja.
    * Added CSV and XLSX import/export for bulk rule editing.
    * Added spreadsheet templates with platform/version metadata for round-trip rule updates.
    * Improved DDM generation so multiple rules targeting the same declaration/key are deep-merged instead of overwriting each other.
    * Added support for displaying generated DDM declaration JSON directly in guidance documents.
    * Added support for the newer com.apple.configuration.app.settings DDM workflows.
    * Improved generated HTML with light/dark theme support.
    * Made Markdown/tree generation more platform-aware.
    * Added pre-release benchmark awareness to generated guidance.
    * Improved SCAP generation metadata, including generated timestamps and OS-version handling.
    * Reduced unnecessary generator delays to improve overall generation speed.
    * Added improved handling and escaping for content rendered through Typst/HTML.
* Github/CI Changes
  * Container
    * Rebuilt the project container on Python 3.13 Debian Slim instead of Alpine Linux.
    * Removed Ruby and AsciiDoctor dependencies from the container.
    * Pinned the uv version for more reproducible container builds.
    * Simplified container dependencies by relying on prebuilt Python wheels instead of compiling packages from source.
    * Changed the interactive container shell from sh to bash, including bash completion and an mSCP-specific prompt.
    * Reworked container publishing to build amd64 and arm64 natively in parallel instead of using QEMU emulation.
    * Added separate per-architecture BuildKit caches to improve container build performance.
    * Added a dedicated manifest merge step to publish the final multi-architecture container image.
    * Preserved cosign signing and GitHub attestations for the merged multi-architecture image.
    * Improved container workflow concurrency and centralized branch/revision/tag handling.
    * Added explicit SHA-based image tagging using the resolved source revision.
