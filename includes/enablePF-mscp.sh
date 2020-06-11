#!/bin/bash

#enabling macos application firewall
enable_macos_application_firewall () {

	/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
	/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingopt detail 
	/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on
	/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on 

}

#enabling pf firewall with macsec rules
enable_pf_firewall_with_macsec_rules () {
	macsec_pfctl_plist="/Library/LaunchDaemons/macsec.pfctl.plist"

	if [[ -e "$macsec_pfctl_plist" ]]; then
		echo "LaunchDaemon already exists, flushing and reloading rules..."
		pfctl -e 2> /dev/null
		pfctl -f /etc/pf.conf 2> /dev/null
		return 0
	fi

	# copy system provided launchd for custom ruleset
	cp "/System/Library/LaunchDaemons/com.apple.pfctl.plist" "$macsec_pfctl_plist"
	#allow pf to be enabled when the job is loaded
	/usr/libexec/PlistBuddy -c "Add :ProgramArguments:1 string -e" $macsec_pfctl_plist
	#use new label to not conflict with System's pfctl
	/usr/libexec/PlistBuddy -c "Set :Label macsec.pfctl" $macsec_pfctl_plist

	# enable the firewall
	pfctl -e 2> /dev/null

	#make pf run at system startup
	launchctl enable system/macsec.pfctl
	launchctl bootstrap system $macsec_pfctl_plist

	pfctl -f /etc/pf.conf 2> /dev/null #flush the pf ruleset (reload the rules)   

}

# append the macsec anchors to pf.conf
configure_pf_config_add_macsec_anchors () {

	# check to see if macsec anchors exists
	anchors_exist=$(grep -c '^anchor "macsec_pf_anchors"' /etc/pf.conf)

	if [[ $anchors_exist == "0" ]];then
		echo 'anchor "macsec_pf_anchors"' >> /etc/pf.conf
		echo 'load anchor "macsec_pf_anchors" from "/etc/pf.anchors/macsec_pf_anchors"' >> /etc/pf.conf
	else
		echo "macsec anchors exist, continuing..."
	fi

}


# Create /etc/pf.anchors/macsec_pf_anchors
create_macsec_pf_anchors () {
if [[ -e /etc/pf.anchors/macsec_pf_anchors ]]; then
	echo "macsec Anchor file exists, deleting and recreating..."
	rm -f /etc/pf.anchors/macsec_pf_anchors
fi


cat > /etc/pf.anchors/macsec_pf_anchors <<'ENDCONFIG'

anchor macsec_pf_anchors

#default deny all in, allow all out and keep state
block in all
pass out all keep state

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

#### 

enable_macos_application_firewall
create_macsec_pf_anchors
configure_pf_config_add_macsec_anchors
enable_pf_firewall_with_macsec_rules
