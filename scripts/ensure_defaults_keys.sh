#!/bin/bash

# ensure_defaults_keys.sh
# 
# Helper script to ensure critical defaults keys exist with proper values
# This prevents "does not exist" errors when checking compliance
#
# This script is automatically called by compliance scripts generated from
# generate_guidance.py and runs before compliance checks to initialize
# missing defaults keys that may not exist on fresh systems.
#
# The script creates keys with compliant values, then mcxrefresh ensures
# Configuration Profiles take precedence over these defaults.

# Get current user
CURRENT_USER=$(/usr/bin/stat -f "%Su" /dev/console)

echo "Ensuring critical defaults keys exist for user: $CURRENT_USER"

# Control Center keys that may not exist on fresh systems
echo "Setting Control Center menu visibility..."
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.controlcenter "NSStatusItem Visible Bluetooth" -int 1 2>/dev/null
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.controlcenter "NSStatusItem Visible WiFi" -int 1 2>/dev/null

# Accessibility privacy keys
echo "Setting Accessibility privacy preferences..."
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.Accessibility AXSAudioDonationSiriImprovementEnabled -bool false 2>/dev/null

# Safari privacy and security keys
echo "Setting Safari privacy and security preferences..."
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.Safari IncludeDevelopMenu -bool false 2>/dev/null
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.Safari ShowStatusBar -bool true 2>/dev/null
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.Safari WebKitPreferences.fraudulentWebsiteWarningEnabled -bool true 2>/dev/null
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.Safari ShowFullURLInSmartSearchField -bool true 2>/dev/null

# Terminal security keys
echo "Setting Terminal security preferences..."  
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.Terminal SecureKeyboardEntry -bool true 2>/dev/null

# Search and Siri privacy keys
echo "Setting Search and Siri privacy preferences..."
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.assistant.support "Search Queries Data Sharing Status" -int 2 2>/dev/null

echo "Defaults keys initialization complete"

# Refresh managed preferences to ensure MDM takes precedence
echo "Refreshing managed preferences..."
/usr/bin/mcxrefresh -u $(/usr/bin/id -u "$CURRENT_USER") 2>/dev/null

echo "Done"