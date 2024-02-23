#!/bin/bash
# Title          : enablePF-mscp.sh
# Description    : This script will configure the packet filter `pf` with the settings recommended by the macOS Security Compliance Project (MSCP)
# Author		 : Dan Brodjieski
# Date           : 2023-10-05
# Version        : 1.0    
# Usage			 : enablePF-mscp.sh [--uninstall]
# Notes          : Script must be run with privileges
#				 : Configuring `pf` with a content filter installed may have unexpected results
# Changelog		 : 2023-10-05 - Added --uninstall parameter, refactored script for better functionality 

#### verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root or with sudo, exiting..."
    exit 1
fi

#### Setup environment
launchd_pfctl_plist="/Library/LaunchDaemons/mscp.pfctl.plist"
legacy_launchd_plist="/Library/LaunchDaemons/macsec.pfctl.plist"

mdm_managed=$(/usr/bin/osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall').objectIsForcedForKey('EnableFirewall')")

#### Functions ####

#enabling macos application firewall
enable_macos_application_firewall () {
	echo "The macOS application firewall is not managed by a profile, enabling from CLI"
	/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
	/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingopt detail
	/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on
	/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on

}

#enabling pf firewall with mscp rules
enable_pf_firewall_with_mscp_rules () {
	echo "Creating LaunchDeamon to load the MSCP rules"
	if [[ -e "$launchd_pfctl_plist" ]]; then
		echo "LaunchDaemon already exists, flushing and reloading rules..."
		pfctl -e 2> /dev/null
		pfctl -f /etc/pf.conf 2> /dev/null
		return 0
	fi

	# copy system provided launchd for custom ruleset
	cp "/System/Library/LaunchDaemons/com.apple.pfctl.plist" "$launchd_pfctl_plist"
	#allow pf to be enabled when the job is loaded
	/usr/libexec/PlistBuddy -c "Add :ProgramArguments:1 string -e" $launchd_pfctl_plist
	#use new label to not conflict with System's pfctl
	/usr/libexec/PlistBuddy -c "Set :Label mscp.pfctl" $launchd_pfctl_plist

	# enable the firewall
	pfctl -e 2> /dev/null

	#make pf run at system startup
	launchctl enable system/mscp.pfctl
	launchctl bootstrap system $launchd_pfctl_plist

	pfctl -f /etc/pf.conf 2> /dev/null #flush the pf ruleset (reload the rules)

}

# append the mscp anchors to pf.conf
configure_pf_config_add_mscp_anchors () {
	echo "Adding the MSCP anchors to /etc/pf.conf"
	# check to see if mscp anchors exists
	anchors_exist=$(grep -c '^anchor "mscp_pf_anchors"' /etc/pf.conf)

	if [[ $anchors_exist == "0" ]];then
		echo 'anchor "mscp_pf_anchors"' >> /etc/pf.conf
		echo 'load anchor "mscp_pf_anchors" from "/etc/pf.anchors/mscp_pf_anchors"' >> /etc/pf.conf
	else
		echo "mscp anchors exist, continuing..."
	fi

}


# Create /etc/pf.anchors/mscp_pf_anchors
create_mscp_pf_anchors () {
	echo "Creating the MSCP anchor configuration file"
if [[ -e /etc/pf.anchors/mscp_pf_anchors ]]; then
	echo "mscp Anchor file exists, deleting and recreating..."
	rm -f /etc/pf.anchors/mscp_pf_anchors
fi


cat > /etc/pf.anchors/mscp_pf_anchors <<'ENDCONFIG'

anchor mscp_pf_anchors

#default deny all in, allow all out and keep state
block in all
pass out all keep state

#pass in all packets from localhost
pass in from 127.0.0.1

## Allow DHCP
pass in inet proto udp from port 67 to port 68
pass in inet6 proto udp from port 547 to port 546

## Allow incoming SSH
pass in proto tcp to any port 22

#apple file service --port 548-- pf firewall rule
block in log proto tcp to any port { 548 }

#bonjour component SSDP --port 1900-- pf firewall rule
block log proto udp to any port 1900

#finger --port 79-- pf firewall rule
block log proto tcp to any port 79

#ftp --ports 20 21-- pf firewall rule
block in log proto { tcp udp } to any port { 20 21 }

#http --port 80-- pf firewall rule
block in log proto { tcp udp } to any port 80

#icmp pf firewall rule
block in log proto icmp

#imap --port 143-- pf firewall rule
block in log proto tcp to any port 143

#imaps --port 993-- pf firewall rule
block in log proto tcp to any port 993

#iTunes sharing --port 3689-- pf firewall rule
block log proto tcp to any port 3689

#mDNSResponder --port 5353-- pf firewall rule
block log proto udp to any port 5353

#nfs --port 2049-- pf firewall rule
block log proto tcp to any port 2049

#optical drive sharing --port 49152-- pf firewall rule
block log proto tcp to any port 49152

#pop3 --port 110-- pf firewall rule
block in log proto tcp to any port 110

#pop3s --port 995-- pf firewall rule
block in log proto tcp to any port 995

#remote apple events --port 3031-- pf firewall rule
block in log proto tcp to any port 3031

#screen_sharing --port 5900-- pf firewall rule
block in log proto tcp to any port 5900
#allow screen sharing from localhost while tunneled via SSH
pass in quick on lo0 proto tcp from any to any port 5900

#smb --ports 139 445 137 138-- pf firewall rule
block in log proto tcp to any port { 139 445 }
block in log proto udp to any port { 137 138 }

#smtp --port 25-- pf firewall rule
block in log proto tcp to any port 25

#telnet --port 23-- pf firewall rule
block in log proto { tcp udp } to any port 23

#tftp --port 69-- pf firewall rule
block log proto { tcp udp } to any port 69

#uucp --port 540-- pf firewall rule
block log proto tcp to any port 540

ENDCONFIG
}

# function to remove legacy setup if exists
remove_macsec_setup() {
	echo "References to macsec appear to exist, removing..."

	launchctl disable system/macsec.pfctl
	launchctl bootout system $legacy_launchd_plist
	rm -rf $legacy_launchd_plist
	
	# check to see if macsec anchors exists
	anchors_exist=$(grep -c '^anchor "macsec_pf_anchors"' /etc/pf.conf)

	if [[ ! $anchors_exist == "0" ]];then
		sed -i "" '/macsec/d' /etc/pf.conf
	else
		echo "macsec anchors do not exist, continuing..."
	fi

	rm -f /etc/pf.anchors/macsec_pf_anchors
}

uninstall_mscp_pf(){
	echo "Removing MSCP configuration files from pf"
	if [[ -e "$launchd_pfctl_plist" ]]; then
		echo "LaunchDaemon exists, unloading and removing"
		#remove mscp pf components from launchd
		launchctl disable system/mscp.pfctl
		launchctl bootout system $launchd_pfctl_plist
		rm -rf $launchd_pfctl_plist
	fi
	
	# check to see if mscp anchors exists
	anchors_exist=$(grep -c '^anchor "mscp_pf_anchors"' /etc/pf.conf)

	if [[ ! $anchors_exist == "0" ]];then
		sed -i "" '/mscp/d' /etc/pf.conf
	else
		echo "mscp anchors do not exist, continuing..."
	fi

	rm -f /etc/pf.anchors/mscp_pf_anchors

	# flush rules and reload pf
	echo "Flushing rules and reloading pf"
	pfctl -f /etc/pf.conf 2> /dev/null #flush the pf ruleset (reload the rules)   

}

#### Main Script ####

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -u|--uninstall)
      UNINSTALL="true"
      shift # past argument
      shift # past value
      ;;
	-*|--*)
      echo "Unknown option $1"
	  exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [[ $UNINSTALL == "true" ]]; then
	if [[ -e "$legacy_launchd_plist" ]]; then
		remove_macsec_setup
	fi
	uninstall_mscp_pf
	exit 0
fi

# check to see if a profile has enabled the firewall.  If it hasn't, then CLI can be used to enable
if [[ "$mdm_managed" == "false" ]];then
	 enable_macos_application_firewall
fi

# clean up any legacy configurations
if [[ -e "$legacy_launchd_plist" ]]; then
	echo "References to macsec appear to exist, removing..."
	remove_macsec_setup
fi

# create mscp anchors file
create_mscp_pf_anchors

# add the anchors to the /etc/pf.conf file
configure_pf_config_add_mscp_anchors

# create specific launch daemon for mscp configuration
enable_pf_firewall_with_mscp_rules
