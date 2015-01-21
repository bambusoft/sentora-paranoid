#!/usr/bin/env bash

# Unofficial Sentora Automated Security Script
# =============================================
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  OS VERSION supported: Ubuntu 14.04 32bit and 64bit
#
#  Author Mario Rodriguez Somohano, sentora-paranoid (at) open-source.tk
#  based on the original sentora installer script developed by 
#  Pascal Peyremorte and others.
#
# Parameters: [|revert|clean|status]
#	No parameter means install
#	revert - will try to set te sentora environment to its initial state
#	clean  - removes log and tree files
#	status - will show services status

if [[ "$1" = "clean" ]] ; then
	#rm -f sentora-paranoid.dat > /dev/null
	rm -f sentora-paranoid-*.{log,new,org} > /dev/null
	clear
	echo -e "Cleaned log and temporary files\n"
	exit
fi

SENTORA_PARANOID_VERSION="1.0.0-dev-snapshot"	# This installer version
SENTORA_INSTALLER_VERSION="1.0.0-RC1"	# Script version used to install sentora
SENTORA_CORE_VERSION="1.0.0-RC1"		# Sentora core versión
SENTORA_PRECONF_VERSION="1.0.0-RC1"		# Preconf used by sentora script installer

PANEL_PATH="/etc/sentora"
PANEL_DATA="/var/sentora"

COLOR_RED="\e[1;31m"
COLOR_GRN="\e[1;32m"
COLOR_YLW="\e[1;33m"
COLOR_END="\e[0m"

change() {
	# $1=[-R|blank] $2=permissions $3=usr $4=grp $5=[file|path]
	if [ -z $1 ] ; then
		symbol="-"
	else
		symbol=$1
	fi
	echo "[$symbol] $2 $3:$4 => $5"
	chown $1 $3:$4 $5
	chmod $1 $2 $5
}

check_status() {
	status=$(service mysql status)
	echo "MySQL: $status"
	status=$(service postfix status)
	echo "Postfix: $status"
	status=$(/etc/init.d/sp-policyd status)
	echo "sp-policyd: $status"
	status=$(service opendkim status)
	echo "Opendkim: $status"
	status=$(/etc/init.d/amavis status)
	echo "amavis-new: $status"
	status=$(service spamassassin status)
	echo "Spamassassin: $status"
	status=$(service clamav-daemon status)
	echo "Clamav: $status"
	status=$(service clamav-freshclam status)
	echo "Fresh Clamav: $status"
	status=$(apache2ctl -M | grep "php5")
	echo "PHP: $status"
	status=$(service apache2 status)
	echo "Apache: $status"
	status=$(service dovecot status)
	echo "Dovecot: $status"
	status=$(service proftpd status)
	echo "ProFTPd: $status"
	status=$(service bind9 status)
	echo "Bind: $status"
	status=$(service atd status)
	echo "atd: $status"
	status=$(service cron status)
	echo "Cron: $status"
	status=$(iptables -L -v | grep "INPUT")
	echo "iptables: $status"
	status=$(service fail2ban status | grep "is")
	echo "fail2ban: $status"
	status=$(apparmor_status)
	echo "apparmor: $status"
}

STORE_TREE="true"

save_tree() {
	# $1 path to save $2 ext
	if [ -d $1 ] ; then
		echo "Writing file permissions for: $1"
		/usr/bin/tree -pugfal $1 >> sentora-paranoid-$$.$2
	fi
}


#====================================================================================
#--- Display the 'welcome' splash/user warning info..
clear
echo -e "\n#########################################################################"
echo "#   Welcome to sentora-paranoid, the unofficial Sentora security script #"
echo "#########################################################################"

#====================================================================================
# Check if the user is 'root' before allowing any modification
if [ $UID -ne 0 ]; then
	echo -e "$COLOR_RED Execuion failed: you must be logged in as 'root' to proceed. $COLOR_END"
	echo "Use command 'sudo -i', then enter root password and then try again."
	exit 1
fi

#====================================================================================
# User is requesting to see services status
if [[ "$1" = "status" ]] ; then
	clear
	check_status
	exit
fi

#====================================================================================
#  Ensure the OS is compatible with the script
# (Centos 6 & 7 and Ubuntu 12.04 are considered but not tested, feel free to send feedback)
echo -e "\nChecking that minimal requirements are ok"
BITS=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')
if [ -f /etc/centos-release ]; then
    OS="CentOs"
    VERFULL=$(sed 's/^.*release //;s/ (Fin.*$//' /etc/centos-release)
    VER=${VERFULL:0:1} # return 6 or 7
elif [ -f /etc/lsb-release ]; then
    OS=$(grep DISTRIB_ID /etc/lsb-release | sed 's/^.*=//')
    VER=$(grep DISTRIB_RELEASE /etc/lsb-release | sed 's/^.*=//')
else
    OS=$(uname -s)
    VER=$(uname -r)
fi

echo "Detected : $OS  $VER  $BITS"

if [[ "$OS" = "CentOs" && ("$VER" = "6" || "$VER" = "7" ) || 
      "$OS" = "Ubuntu" && ("$VER" = "12.04" || "$VER" = "14.04" ) ]] ; then 
    echo "Ok"
	if [[ "$OS" = "Ubuntu" ]] ; then
		PACKAGE_INSTALLER="apt-get -yqq install"
		PACKAGE_REMOVER="apt-get -yqq remove"
		HTTP_USER="www-data"
		HTTP_GROUP="www-data"
	fi
	if [[ "$OS" = "CentOs" ]] ; then
		PACKAGE_INSTALLER="yum -y -q install"
		PACKAGE_REMOVER="yum -y -q remove"
		HTTP_USER="apache"
		HTTP_GROUP="apache"
	fi
	if [[ "$OS" = "Ubuntu" && "$VER" = "14.04" ]] ; then
	    echo -e "$COLOR_GRN This OS is supported by sentora-paranoid team $COLOR_END\n"
	else
	    echo -e "$COLOR_YLW WARNING: OS=$OS $VER is not being tested by sentora-paranoid team, continue at your own risk $COLOR_END\n"
	fi
else
    echo -e "$COLOR_RED Sorry, this OS is not supported by sentora-paranoid. $COLOR_END\n" 
    exit 1
fi

#====================================================================================
# Tree tool used to store file permissions to compare original and final states
if [[ "$STORE_TREE" = "true" ]] ; then
	if [ -f /usr/bin/tree ] ; then
		echo "Tree tool is already installed, nice!"
	else
		echo "Installing tree required to review file permissions"
		$PACKAGE_INSTALLER tree
	fi
fi

#====================================================================================
# Check if the administrator is requesting to revert sentora-paranoid
if [[ "$1" = "revert" ]] ; then
	    echo -e "$COLOR_YLW Reversion requested, this will disable security packages installed and set file permissons to its original state. $COLOR_END\n"
		REVERT="true"
		ACTION="revert"
else
		REVERT="false"
		ACTION="install"
fi

#====================================================================================
# Check for some common control security packages that we know will affect the installation/operating of sentora-paranoid.
echo "Checking for preinstalled security packages"
if [[ "$OS" = "Ubuntu" ]]; then
	# UFW must be disabled
	if [ -e /usr/sbin/ufw ] ; then
	 UFWstatus=$(ufw status | sed -e "s/Status: //")
	 if [[ "$UFWstatus" != "inactive" ]] ; then
		echo -e "$COLOR_RED Execuion failed: you must disable UncomplicatedFirewall (ufw) to proceed. $COLOR_END"
		exit 1
	 fi
	fi
	# iptables ipv4 must be installed by default in Ubuntu 14.04
	if [ -e /sbin/iptables ] ; then
	 iptables_version=$(iptables --version | sed -e "s/iptables //")
	 if [ -z "$iptables_version" ] ; then
		echo -e "$COLOR_RED Execuion failed: iptables is not preinstalled/running on this system. $COLOR_END"
		exit 1
	 fi
	fi
	# iptables ipv6 must be installed by default in Ubuntu 14.04
	if [ -e /sbin/ip6tables ] ; then
	 ip6tables_version=$(ip6tables --version | sed -e "s/ip6tables //")
	 if [ -z "$ip6tables_version" ] ; then
		echo -e "$COLOR_RED Execuion failed: ip6tables is not preinstalled/running on this system. $COLOR_END"
		exit 1
	 fi
	fi
	# fail2ban must not be preinstalled
	if [[ "$REVERT" = "false" ]] ; then
		if [ -e /etc/init.d/fail2ban ] ; then
			echo -e "$COLOR_RED Execuion failed: fail2ban is preinstalled on this system. $COLOR_END"
			echo "It appears that a failure log scanner is already installed on your server;"
			echo " This installer is designed to install and configure sentora-paranoid on a clean OS installation with Sentora installed only!"
			echo -e "\nPlease re-install your OS and sentora $SENTORA_CORE_VERSION before attempting to install senora-paranoid using this script."
			exit 1
		fi
	fi
	echo -e "Ok\n"
else
    echo -e "$COLOR_YLW WARNING: OS=$OS $VER is not being tested by sentora-paranoid team, packages not checked $COLOR_END\n"	
fi

#====================================================================================
# Obtain current user/group and administrator(sudoer) user/group
datfile=sentora-paranoid.dat
if [[ "$REVERT" = "false" ]] ; then
	echo "Some installations require more security than others, you may want to"
	echo "have an unprivileged user to change configurations only, or you want to"
	echo "have more than one administrator all of them belonging to an administration"
	echo "group, so you have three choices to select user/group names below:"
	echo ''
	echo "	adminuser/adminuser (which is in the sudoers list)"
	echo "	adminuser/admingroup (adminuser is in the sudoers list)"
	echo "	root/root (more secure but risky at the same time)"
	echo ''
	echo "In doubt, please use the default values or root/root if you know what are you doing"
	echo ''
	if [ -z "$SUDO_USER" ] ; then
		ADMIN_USR="root"
		ADMIN_GRP="root"
	else
		ADMIN_USR=$SUDO_USER
		ADMIN_GRP=$(id -g -n $ADMIN_USR)
	fi
	read -e -p "Please enter administrative user name: " -i "$ADMIN_USR" ADMIN_USR
	if [ -z "$ADMIN_USR" ] ; then
		ADMIN_USR="root"
	else
		EXIST=$(grep "$ADMIN_USR:" /etc/passwd)
		if [ -z "$EXIST" ] ; then
			echo -e "$COLOR_RED Execuion failed: administrative user does not exist. $COLOR_END"
			exit 1
		fi
	fi
	read -e -p "Please enter administrative group name: " -i "$ADMIN_GRP" ADMIN_GRP
	if [ -z "$ADMIN_GRP" ] ; then
		ADMIN_GRP="root"
	else
		EXIST=$(grep "$ADMIN_GRP:" /etc/group)
		if [ -z "$EXIST" ] ; then
			echo -e "$COLOR_RED Execuion failed: administrative group does not exist. $COLOR_END"
			exit 1
		fi
	fi
	echo -e "Using:$COLOR_GRN $ADMIN_USR : $ADMIN_GRP $COLOR_END as the administrative username:groupame"
	echo "ADMIN_USR:$ADMIN_USR" > $datfile
	echo "ADMIN_GRP:$ADMIN_GRP" >> $datfile
	
else
	ADMIN_USR=$(grep "ADMIN_USR" $datfile | sed "s@ADMIN_USR:@@")
	ADMIN_GRP=$(grep "ADMIN_GRP" $datfile | sed "s@ADMIN_GRP:@@")
fi

while true; do
	echo ""
	read -e -p "All is ok, do you want to $ACTION sentora-paranoid (Y/n)? " -i 'y' answer
	case $answer in
		[Yy]* ) break;;
		[Nn]* ) exit;;
	esac
done
clear

#====================================================================================
# START INSTALL/REVERT
#====================================================================================
logfile=sentora-paranoid-$$.log
FQDN=$(grep "mydomain =" $PANEL_PATH/configs/postfix/main.cf | sed "s@mydomain = @@")
#local_ip=$(ifconfig eth0 | sed -En 's|.*inet [^0-9]*(([0-9]*\.){3}[0-9]*).*$|\1|p')
local_ip=$(ip addr show | awk '$1 == "inet" && $3 == "brd" { sub (/\/.*/,""); print $2 }')

touch $logfile
exec > >(tee $logfile)
exec 2>&1

date
echo ""
echo "sentora-paranoid version: $SENTORA_PARANOID_VERSION"
echo "sentora-installer version: $SENTORA_INSTALLER_VERSION"
echo "sentora-preconf version: $SENTORA_PRECONF_VERSION"
echo "sentora-core version: $SENTORA_CORE_VERSION"
echo ""
echo "Action requested: $ACTION on server: $OS  $VER  $BITS"
uname -a
echo ""
echo "Admin user: $ADMIN_USR"
echo "Admin group: $ADMIN_GRP"
echo "Fully Qualified Domain Name (FQDN): $FQDN"
echo "Local IP: $local_ip"
echo ""
echo "UncomplicatedFirewall status: $UFWstatus"
echo "iptables version: $iptables_version"
echo ""

if [[ "$STORE_TREE" = "true" ]] ; then
	# Store original file permissions
	echo "--Storing original file permissions"
	if [ -f sentora-paranoid-$$.1st ] ; then
		truncate -s 0 sentora-paranoid-$$.1st
	fi
	save_tree /etc/sentora 1st
	save_tree /etc/mysql 1st
	save_tree /etc/postfix 1st
	save_tree /etc/php5 1st
	save_tree /etc/apache2 1st
	save_tree /etc/dovecot 1st
	save_tree /etc/proftpd 1st
	save_tree /etc/bind 1st
	save_tree /etc/fail2ban 1st
	save_tree /etc/apparmor.d 1st
fi

#====================================================================================
#--- Download sentora-paranoid preconf archive from site
echo -e "\n-- Working with sentora-paranoid preconf, Please wait, this may take several minutes, the installer will continue after this is complete!"
SENTORA_PARANOID_CONFIG_PATH="$PANEL_PATH/configs/sentora-paranoid"
SENTORA_PARANOID_BACKUP_PATH="$SENTORA_PARANOID_CONFIG_PATH/backup"

if [[ "$REVERT" = "false" ]] ; then
	# Get latest sentora-paranoid/preconf
	while true; do
		wget -nv -O /tmp/preconf.zip http://sentora-paranoid.open-source.tk/installers/$SENTORA_PARANOID_VERSION/preconf.zip
		if [ -f /tmp/preconf.zip ] ; then
			unzip -oq /tmp/preconf.zip -d /tmp
			if [ -d /tmp/preconf/preconf ] ; then
				PRECONF_TEMP=/tmp/preconf/preconf
			else
				PRECONF_TEMP=/tmp/preconf
			fi
			mkdir -vp $SENTORA_PARANOID_CONFIG_PATH
			cp -vr $PRECONF_TEMP/* $SENTORA_PARANOID_CONFIG_PATH
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH
			chown -R root:root $SENTORA_PARANOID_CONFIG_PATH
			rm -rf /tmp/preconf.zip /tmp/preconf
			break;
		else
			echo -e "$COLOR_RED Execuion failed: Cannot get latest sentora-paranoid/preconf. $COLOR_END"
			echo "If you quit now, you can run again the installer later."
			read -e -p "Press r to retry or q to quit the installer? " resp
			case $resp in
				[Rr]* ) continue;;
				[Qq]* ) exit 3;;
			esac
		fi
	done
fi

#====================================================================================
#--- Get current sshd port to avoid administrative blocking by new firewall rules
echo -e "\n-- Obtaining current sshd port"
SSHD_PORT=$( cat /etc/ssh/sshd_config | grep "Port" | sed -e "s/Port //" )
re='^[0-9]+$'
if ! [[ $SSHD_PORT =~ $re ]] ; then
   echo "NOTICE: Could not determine current ssh port number, using default."
   echo "You must change firewall rules manually if this is not the port you are using to connect to this server"
   echo "otherwise, you will be blocked to access the server"
   SSHD_PORT=22;
fi
echo "SSHD Port: $SSHD_PORT"
if [[ "$REVERT" = "false" ]] ; then
	sed "s@%%SSHDPORT%%@$SSHD_PORT@g" $SENTORA_PARANOID_CONFIG_PATH/iptables/iptables.firewall.orig > $SENTORA_PARANOID_CONFIG_PATH/iptables/iptables.firewall.rules 
	sed "s@%%SSHDPORT%%@$SSHD_PORT@g" $SENTORA_PARANOID_CONFIG_PATH/iptables/ip6tables.firewall.orig > $SENTORA_PARANOID_CONFIG_PATH/iptables/ip6tables.firewall.rules 
	sed "s@%%SSHDPORT%%@$SSHD_PORT@g" $SENTORA_PARANOID_CONFIG_PATH/fail2ban/jail.local.orig > $SENTORA_PARANOID_CONFIG_PATH/fail2ban/jail.local
fi

#====================================================================================
#--- Stop current security services in every case (revert|install)
echo -e "\n-- Stoping security services"
if [[ "$OS" = "Ubuntu" ]]; then
	if [[ "$UFWstatus" != "inactive" ]] ; then
		ufw disable
	fi
	if [ -n "$iptables_version" ] ; then
		if [[ "$REVERT" = "false" ]] ; then	
			if [ -f $SENTORA_PARANOID_BACKUP_PATH/iptables/ip4tables.txt ] ; then
				echo "ip4tables rules file already backed up"
			else
				mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/iptables
				iptables-save > $SENTORA_PARANOID_BACKUP_PATH/iptables/ip4tables.txt
				echo "ip4tables backed up"
			fi
		fi
		echo "Cleaning ipv4 firewall rules"
		iptables -X
		iptables -t nat -F
		iptables -t nat -X
		iptables -t mangle -F
		iptables -t mangle -X
		iptables -P INPUT ACCEPT
		iptables -P FORWARD ACCEPT
		iptables -P OUTPUT ACCEPT
	fi
	if [ -n "$ip6tables_version" ] ; then
		if [[ "$REVERT" = "false" ]] ; then
			if [ -f $SENTORA_PARANOID_BACKUP_PATH/iptables/ip6tables.txt ] ; then
				echo "ip6tables rules file already backed up"
			else
				mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/iptables
				ip6tables-save > $SENTORA_PARANOID_BACKUP_PATH/iptables/ip6tables.txt
				echo "ip6tables backed up"
			fi
		fi
		echo "Cleaning ipv6 firewall rules"
		ip6tables -X
		ip6tables -t mangle -F
		ip6tables -t mangle -X
		ip6tables -P INPUT ACCEPT
		ip6tables -P FORWARD ACCEPT
		ip6tables -P OUTPUT ACCEPT
	fi
	if [ -e /etc/init.d/fail2ban ] ; then
		echo "Stoping fail2ban service"
		/etc/init.d/fail2ban stop
	fi
fi
# WARNING: At this point firewall is accepting everything and fail2ban is down

#====================================================================================
#--- Install or remove used packages
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		echo -e "\n-- Downloading and installing required tools..."
		$PACKAGE_INSTALLER openssl iptables iptables-persistent fail2ban apparmor apparmor-utils libapache2-mod-apparmor ipset 
		$PACKAGE_INSTALLER opendkim opendkim-tools amavisd-new spamassassin spamc clamav clamav-base libclamav6 clamav-daemon clamav-freshclam
		$PACKAGE_INSTALLER libswitch-perl libnet-dns-perl libmail-spf-perl pyzor razor arj bzip2 cabextract cpio file gzip nomarch pax rar unrar unzip zip
		# Do not install apparmor-profiles unless you really know what are you doing
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		echo -e "\n-- Removing installed tools..."
		$PACKAGE_REMOVER fail2ban libapache2-mod-apparmor
		$PACKAGE_REMOVER opendkim opendkim-tools amavisd-new spamassassin spamc clamav clamav-base libclamav6 clamav-daemon clamav-freshclam
		# Remove iptables is a bad idea, we will set to minimal(required) open ports later
		# Remove ipset is a bad idea we flush lists later
		# Remove apparmor is a bad idea, we will set to minimal(complain) rules later
		# If you really need to disable apparmor then use:
		#	sudo service apparmor stop
		#	sudo update-rc.d -f apparmor remove
	fi
fi

#====================================================================================
#--- Sentora
echo -e "\n-- Sentora security"
PWDFILE="$PANEL_PATH/panel/cnf/db.php"
MYSQL=`which mysql`
RP=$(grep "pass" $PWDFILE | sed -e "s@\$pass = '@@" -e "s@';@@")
PP="$$sp$$"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		Q1="USE sentora_core;"
		Q2="UPDATE x_settings SET so_value_tx='php_admin_value suhosin.executor.func.blacklist \"eval, passthru, show_source, shell_exec, system, pcntl_exec, popen, pclose, proc_open, proc_nice, proc_terminate, proc_get_status, proc_close, leak, apache_child_terminate, posix_kill, posix_mkfifo, posix_setpgid, posix_setsid, posix_setuid, escapeshellcmd, escapeshellarg, exec\"' WHERE so_name_vc='suhosin_value';"
		SQL="${Q1}${Q2}"
		$MYSQL -h localhost -u root "-p$RP" -e "$SQL"
		echo "NOTICE: PHP Function [eval] was disabled, this may cause conflicts whit some php scripts"
		Q1="USE sentora_postfix;"
		Q2="ALTER TABLE mailbox ADD COLUMN msgquota int(10) unsigned NOT NULL DEFAULT '0';"
		Q3="ALTER TABLE mailbox ADD COLUMN msgtally int(10) unsigned NOT NULL DEFAULT '0';"
		Q4="ALTER TABLE mailbox ADD COLUMN timestamp int(10) unsigned DEFAULT NULL;"
		SQL="${Q1}${Q2}${Q3}${Q4}"
		$MYSQL -h localhost -u root "-p$RP" -e "$SQL"
		echo "NOTICE: sentora_postfix database has changed to manage mail quota"
		Q1="CREATE USER 'paranoid'@'localhost' IDENTIFIED BY '${PP}';"
		Q2="GRANT ALL PRIVILEGES ON sentora_postfix.mailbox TO 'paranoid'@'localhost';"
		Q3="FLUSH PRIVILEGES;"
		SQL="${Q1}${Q2}${Q3}"
		$MYSQL -h localhost -u root "-p$RP" -e "$SQL"
	fi
	# File permissions (there is more efficient ways to do this, but still testing)
	# PANEL PATH
	change "" "644" root root $PANEL_PATH/panel/index.php
	change "" "644" root root $PANEL_PATH/panel/robots.txt
	change "-R" "755" root root $PANEL_PATH/panel/bin
	change "" "644" root root $PANEL_PATH/panel/bin/api.php
	change "" "644" root root $PANEL_PATH/panel/bin/daemon.php
	change "" "ug+s" root root $PANEL_PATH/panel/bin/zsudo
	change "-R" "644" root root $PANEL_PATH/panel/cnf
	change "-R" "644" root root $PANEL_PATH/panel/inc
	change "" "755" root root $PANEL_PATH/panel/cnf
	change "" "755" root root $PANEL_PATH/panel/inc
	find $PANEL_PATH/panel/dryden -type d -exec chmod 755 {} +
	find $PANEL_PATH/panel/dryden -type f -exec chmod 644 {} +
	change "-R" "go-w" root root $PANEL_PATH/panel/etc						# who requires a public writtable directory?
	find $PANEL_PATH/panel/etc -type d -exec chmod 755 {} +
	find $PANEL_PATH/panel/etc -type f -name '*.sh' -exec chmod 755 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.php' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.py' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.c' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.txt' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.js' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.png' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.xml' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.css' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.htm*' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.sql' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.conf' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.gif' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.ico' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name 'README*' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name 'LICENSE*' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.map' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.md' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.mo' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.inc' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.ini' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name '*.xs*' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name 'TEMPLATE*' -exec chmod 644 {} \;
	find $PANEL_PATH/panel/etc -type f -name 'RELEASE*' -exec chmod 644 {} \;
	change "" "644" root root $PANEL_PATH/panel/etc/apps/webmail/CHANGELOG
	change "" "644" root root $PANEL_PATH/panel/etc/apps/webmail/INSTALL
	change "" "644" root root $PANEL_PATH/panel/etc/apps/webmail/UPGRADING
	change "-R" "664" root $HTTP_GROUP $PANEL_PATH/panel/etc/tmp
	find $PANEL_PATH/panel/etc/tmp -type d -exec chmod 775 {} +
	find $PANEL_PATH/panel/etc/tmp -type f -exec chmod 664 {} +
	change "" "775" root $HTTP_GROUP $PANEL_PATH/panel/etc/apps/webmail/temp
	find /etc/zpanel/panel/modules -type d -exec chmod 755 {} +
	find /etc/zpanel/panel/modules -type f -exec chmod 644 {} +
	change "" "755" root root $PANEL_PATH/configs
	change "" "755" root root $PANEL_PATH/docs
	change "" "755" root root $PANEL_PATH/panel
	echo "NOTICE: $PANEL_PATH file permissions changed, this will affect core and module updates"
	# PANEL DATA
	change "-R" "775" www-data www-data $PANEL_DATA
	change "" "775" vmail mail $PANEL_DATA/vmail
	echo "NOTICE: $PANEL_DATA file permissions changed, this will affect users directories"
else
	if [[ "$OS" = "Ubuntu" ]]; then
		Q2="UPDATE x_settings SET so_value_tx='php_admin_value suhosin.executor.func.blacklist \"passthru, show_source, shell_exec, system, pcntl_exec, popen, pclose, proc_open, proc_nice, proc_terminate, proc_get_status, proc_close, leak, apache_child_terminate, posix_kill, posix_mkfifo, posix_setpgid, posix_setsid, posix_setuid, escapeshellcmd, escapeshellarg, exec\"' WHERE so_name_vc='suhosin_value';"
		SQL="${Q1}${Q2}"
		$MYSQL -h localhost -u root "-p$RP" -e "$SQL"
	fi
	# File permissions
	# PANEL PATH
	change "-R" "777" root root $PANEL_PATH
	change "" "ug+s" root root $PANEL_PATH/panel/bin/zsudo
	# PANEL DATA
	change "-R" "777" www-data www-data $PANEL_DATA
fi

#====================================================================================
#--- mysql
echo -e "\n-- MySQL security"
DATADIR=$(grep "datadir" /etc/mysql/my.cnf | sed "s@datadir.*= @@")
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		# backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/mysql ] ; then
			echo "MySQL config files already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/mysql
			cp -v /etc/mysql/my.cnf $SENTORA_PARANOID_BACKUP_PATH/mysql
		fi
		# Allow authentication warnings
		sed -i "s@log_error =.*@log_error = /var/log/mysql/error.log\nlog-warnings = 2@" /etc/mysql/my.cnf
		# File permissions		
		change "" "600" root root /etc/mysql/debian.cnf
		change "" "g+w" root $ADMIN_GRP /etc/mysql/my.cnf
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/mysql ] ; then
			cp -v $SENTORA_PARANOID_BACKUP_PATH/mysql/my.cnf /etc/mysql 
		else
			echo "Original sentora postfix config files unchanged"
		fi
		# File permissions
		change "" "600" root root /etc/mysql/debian.cnf
		change "" "g-w" root root /etc/mysql/my.cnf
	fi
fi

#====================================================================================
#--- Openssl dummy certificate, you need to change this using real data or use a valid certificate
echo -e "\n-- Openssl certificates"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		echo "Creating new CA please enter a new rootCA password and requested data"
		openssl genrsa -des3 -out $SENTORA_PARANOID_CONFIG_PATH/openssl/keys/root-ca.key 2048 -config $SENTORA_PARANOID_CONFIG_PATH/openssl/openssl.cnf
		echo "Generating root-ca certificate please provide previously rootCA password"
		openssl req -new -x509 -days 365 -subj "/C=MX/ST=Jalisco/L=Guadalajara/O=Sentora Paranoid Ltd/OU=Sentora Paranoid Certification Authority/CN=sentora-paranoid/emailAddress=root@${FQDN}" -key $SENTORA_PARANOID_CONFIG_PATH/openssl/keys/root-ca.key -out $SENTORA_PARANOID_CONFIG_PATH/openssl/certs/root-ca.crt -config $SENTORA_PARANOID_CONFIG_PATH/openssl/openssl.cnf
		echo "Generating root-ca PEM files please provide previously rootCA password"
		openssl x509 -inform PEM -in $SENTORA_PARANOID_CONFIG_PATH/openssl/certs/root-ca.crt > $SENTORA_PARANOID_CONFIG_PATH/openssl/certs/root-ca.pem
		openssl rsa -in $SENTORA_PARANOID_CONFIG_PATH/openssl/keys/root-ca.key -text > $SENTORA_PARANOID_CONFIG_PATH/openssl/keys/root-ca.pem
		echo "Generating server: $FQDN certificate request"
		openssl req -newkey rsa:2048  -subj "/C=MX/ST=Jalisco/L=Guadalajara/O=Sentora Paranoid Ltd/OU=Sentora Paranoid Certification Authority/CN=${FQDN}/emailAddress=root@${FQDN}" -keyout $SENTORA_PARANOID_CONFIG_PATH/openssl/keys/${FQDN}.key -nodes -out $SENTORA_PARANOID_CONFIG_PATH/openssl/requests/${FQDN}.req -config $SENTORA_PARANOID_CONFIG_PATH/openssl/openssl.cnf
		echo "Generating server: $FQDN certificate, please sign and commit"
		openssl ca -config $SENTORA_PARANOID_CONFIG_PATH/openssl/openssl.cnf -days 365 -out $SENTORA_PARANOID_CONFIG_PATH/openssl/certs/${FQDN}.crt -infiles $SENTORA_PARANOID_CONFIG_PATH/openssl/requests/${FQDN}.req
		echo "Supressing $FQDN certificate password for apache"
		openssl rsa -in $SENTORA_PARANOID_CONFIG_PATH/openssl/keys/${FQDN}.key -out $SENTORA_PARANOID_CONFIG_PATH/openssl/keys/${FQDN}-nophrase.key
		change "-R" "600" root root $SENTORA_PARANOID_CONFIG_PATH/openssl
		echo "NOTICE: Dummy certificate for CA and server was created, you need to provide self signed certificates or use a valid certificates"
	fi
fi

#====================================================================================
#--- postfix
echo -e "\n-- Postfix security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		# backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/postfix/sentora ] ; then
			echo "Postfix config files already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/postfix/sentora
			cp -v $PANEL_PATH/configs/postfix/{main,master}.cf $SENTORA_PARANOID_BACKUP_PATH/postfix/sentora
			cp -v $PANEL_PATH/configs/postfix/mynetworks $SENTORA_PARANOID_BACKUP_PATH/postfix/sentora
		fi
		# Reject mails from invalid/unknown fqdn/hostnames
		sed -i "s@reject_unknown_recipient_domain@\treject_non_fqdn_helo_hostname,\n\treject_invalid_helo_hostname,\n\treject_unknown_helo_hostname,\n\treject_unknown_recipient_domain@" $PANEL_PATH/configs/postfix/main.cf
		echo "NOTICE: postfix will reject mails from invalid/unknown fqdn/hostnames , this may reject some legitimate mails"
		sed -i "s@#.*,reject_rbl_client zen.spamhaus.org@\t,reject_rbl_client zen.spamhaus.org@" $PANEL_PATH/configs/postfix/main.cf
		sed -i "s@#.*,reject_rbl_client bl.spamcop.net@\t,reject_rbl_client bl.spamcop.net\n\t,reject_rbl_client cbl.abuseat.org@" $PANEL_PATH/configs/postfix/main.cf
		echo "NOTICE: postfix will check against public black lists, this may reject some legitimate mails"
		# Disable display of the name of the recipient table in the "User unknown" responses
		if ! grep -q "show_user_unknown_table_name" $PANEL_PATH/configs/postfix/main.cf ; then
			echo "show_user_unknown_table_name = no" >> $PANEL_PATH/configs/postfix/main.cf
			# mailbox and message limits
			sed -i "s@mailbox_size_limit@mailbox_size_limit = 20480000 #@" $PANEL_PATH/configs/postfix/main.cf
			sed -i "s@mailbox_size_limit@mailbox_size_limit = 104857600 #@" $PANEL_PATH/configs/postfix/main.cf
			echo "maximal_queue_lifetime = 2d" >> $PANEL_PATH/configs/postfix/main.cf
			echo "bounce_queue_lifetime = 4h" >> $PANEL_PATH/configs/postfix/main.cf
			echo "NOTICE: postfix mailbox and mesage limits are set, this may cause conflicts with users expected behaviour"
			# Limit spammers
			echo "smtpd_error_sleep_time = 20" >> $PANEL_PATH/configs/postfix/main.cf
			echo "smtpd_soft_error_limit = 3" >> $PANEL_PATH/configs/postfix/main.cf
			echo "smtpd_hard_error_limit = 6" >> $PANEL_PATH/configs/postfix/main.cf
			echo "smtpd_junk_command_limit = 4" >> $PANEL_PATH/configs/postfix/main.cf
			echo "NOTICE: postfix spammers limits are set, this may cause conflicts with legitimate users expected behaviour"
			# If we want to allow any host via hosts file
			echo "smtp_host_lookup  = dns,native" >> $PANEL_PATH/configs/postfix/main.cf
			# Remove untrusted network
			sed -i "s@176.31.61.0/28@@" $PANEL_PATH/configs/postfix/mynetworks
		fi
		# TLS
		sed -i "s@smtp_use_tls = no@smtp_use_tls = yes@" $PANEL_PATH/configs/postfix/main.cf
		sed -i "s@smtpd_use_tls = no@smtpd_use_tls = yes@" $PANEL_PATH/configs/postfix/main.cf
		sed -i "s@#smtpd_tls_loglevel = 1@smtp_tls_security_level = may\nsmtpd_tls_loglevel = 1@" $PANEL_PATH/configs/postfix/main.cf
		sed -i "s@#smtpd_tls_received_header@smtpd_tls_received_header@" $PANEL_PATH/configs/postfix/main.cf
		sed -i "s@#smtpd_tls_session_cache_timeout@smtpd_tls_session_cache_timeout@" $PANEL_PATH/configs/postfix/main.cf
		sed -i "s@#tls_random_source@tls_random_source@" $PANEL_PATH/configs/postfix/main.cf
		sed -i "s@#smtpd_tls_key_file@smtpd_tls_key_file = $SENTORA_PARANOID_CONFIG_PATH/openssl/keys/${FQDN}.key\n#@" $PANEL_PATH/configs/postfix/main.cf
		sed -i "s@#smtpd_tls_cert_file@smtpd_tls_cert_file = $SENTORA_PARANOID_CONFIG_PATH/openssl/certs/${FQDN}.crt\n#@" $PANEL_PATH/configs/postfix/main.cf
		sed -i "s@#smtpd_tls_CAfile@smtpd_tls_CAfile = $SENTORA_PARANOID_CONFIG_PATH/openssl/certs/root-ca.crt@" $PANEL_PATH/configs/postfix/main.cf
		# sentora paranoid policy daemon script
		sed -i "s@smtpd_data_restrictions = reject_unauth_pipelining@smtpd_data_restrictions = reject_unauth_pipelining, check_policy_service inet:127.0.0.1:24@" $PANEL_PATH/configs/postfix/main.cf
		cp -v $SENTORA_PARANOID_CONFIG_PATH/postfix/sp-policyd.pl $SENTORA_PARANOID_CONFIG_PATH/postfix/sp-policyd.pl.orig
		sed -i "s@%%LOCAL_IP%%@$local_ip@g" $SENTORA_PARANOID_CONFIG_PATH/postfix/sp-policyd.pl
		sed -i "s@%%DBUSER%%@paranoid@g" $SENTORA_PARANOID_CONFIG_PATH/postfix/sp-policyd.pl
		sed -i "s@%%DBPASS%%@$PP@g" $SENTORA_PARANOID_CONFIG_PATH/postfix/sp-policyd.pl
		cp -v $SENTORA_PARANOID_CONFIG_PATH/postfix/sp-policyd.pl /usr/sbin/sp-policyd.pl
		change "" "ug+x" root $ADMIN_GRP /usr/sbin/sp-policyd.pl
		cp -v $SENTORA_PARANOID_CONFIG_PATH/postfix/sp-policyd /etc/init.d/sp-policyd
		change "" "ug+x" root $ADMIN_GRP /etc/init.d/sp-policyd
		update-rc.d sp-policyd defaults
		touch $PANEL_DATA/logs/sp-policyd.log
		# File permissions
		change "" "g+w" root $ADMIN_GRP $PANEL_DATA/logs/sp-policyd.log
		change "-R" "g+w" root $ADMIN_GRP $PANEL_PATH/configs/postfix
		change "" "g-w" root root $PANEL_PATH/configs/postfix
		service postfix restart
		/etc/init.d/sp-policyd start
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/postfix/sentora ] ; then
			cp -v $SENTORA_PARANOID_BACKUP_PATH/postfix/sentora/{main,master}.cf  $PANEL_PATH/configs/postfix
			cp -v $SENTORA_PARANOID_BACKUP_PATH/postfix/sentora/mynetworks $PANEL_PATH/configs/postfix
		else
			echo "Original sentora postfix config files unchanged"
		fi
		# sentora paranoid policy daemon script
		update-rc.d -f sp-policyd remove
		cp -v $SENTORA_PARANOID_CONFIG_PATH/postfix/sp-policyd.pl.orig $SENTORA_PARANOID_CONFIG_PATH/postfix/sp-policyd.pl
		rm -f /usr/sbin/sp-policyd.pl /etc/init.d/sp-policyd
		# File permissions
		change "-R" "g-w" root root $PANEL_PATH/configs/postfix
		service postfix restart
		/etc/init.d/sp-policyd stop
	fi
fi
#====================================================================================
#--- opendkim
echo -e "\n-- Opendkim"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/opendkim ] ; then
			echo "Opendkim config files already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/opendkim
			cp -v /etc/opendkim.conf $SENTORA_PARANOID_BACKUP_PATH/opendkim
		fi
		mkdir -vp /etc/opendkim /etc/opendkim/keys /var/log/dkim-filter
		change "-R" "775" $ADMIN_USR opendkim  /etc/opendkim
		change "-R" "775" $ADMIN_USR opendkim /etc/opendkim/keys
		change "-R" "775" $ADMIN_USR opendkim /var/log/dkim-filter
		cp -v $SENTORA_PARANOID_CONFIG_PATH/opendkim/opendkim.conf /etc/opendkim/opendkim.conf
		sed -i "s@%%DOMAIN@$FQDN@" /etc/opendkim/opendkim.conf
		ln -vsf opendkim/opendkim.conf /etc/opendkim.conf
		if ! grep -q "inet:12305" $PANEL_PATH/configs/postfix/main.cf ; then
			echo "SOCKET=\"inet:12305@localhost\" # listen on loopback on port 12305" >> /etc/default/opendkim
		fi
		if ! grep -q "milter_protocol" $PANEL_PATH/configs/postfix/main.cf ; then
			echo "" >> $PANEL_PATH/configs/postfix/main.cf
			echo "# dkim with postfix" >> $PANEL_PATH/configs/postfix/main.cf
			echo "milter_protocol = 2" >> $PANEL_PATH/configs/postfix/main.cf
			echo "milter_default_action = accept" >> $PANEL_PATH/configs/postfix/main.cf
		fi
		echo "127.0.0.1" > /etc/opendkim/TrustedHosts
		echo "localhost" >> /etc/opendkim/TrustedHosts
		echo $local_ip >> /etc/opendkim/TrustedHosts
		echo "mail._domainkey.$FQDN $FQDN:mail:/etc/opendkim/keys/$FQDN/mail.private" > /etc/opendkim/KeyTable
		echo "*@$FQDN mail._domainkey.$FQDN" > /etc/opendkim/SigningTable
		echo "NOTICE: opendkim is configured but be sure to add valid keys, signatures and trusted hosts for each domain or legitimate emails could be marked as BULK or SPAM"
		mkdir -vp /etc/opendkim/keys/$FQDN
		/usr/bin/opendkim-genkey -s mail -d /etc/opendkim/keys/$FQDN
		change "-R" "660" $ADMIN_USR opendkim /etc/opendkim/keys/$FQDN
		change "" "770" $ADMIN_USR opendkim /etc/opendkim/keys/$FQDN
		# Both services are restarted in amavis-new section
		#service postfix restart
		#service opendkim restart
	fi
fi

#====================================================================================
#--- spamassasin 
echo -e "\n-- Spamassassin"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		sed -i "s@ENABLED=0@ENABLED=1@" /etc/default/spamassassin	
		sed -i "s@CRON=0@CRON=1@" /etc/default/spamassassin	
		sed -i "s@# rewrite_header@rewrite_header Subject [SPAM] # @" /etc/spamassassin/local.cf
		sed -i "s@# required_score@required_score 3.0 # @" /etc/spamassassin/local.cf
		sed -i "s@# use_bayes@use_bayes@" /etc/spamassassin/local.cf
		sed -i "s@# bayes_auto_learn@bayes_auto_learn@" /etc/spamassassin/local.cf
		# This service is restarted later in amavis-new section
		#service spamassassin restart
	fi
fi

#====================================================================================
#--- clamav 
echo -e "\n-- clamav"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		adduser clamav amavis
		# Both services are restarted in amavis-new section
		#service clamav-daemon restart
		#service clamav-freshclam restart
	fi
fi

#====================================================================================
#--- amavis-new
echo -e "\n-- amavis-new"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		adduser amavis clamav
		sed -i "s@1;@@" /etc/amavis/conf.d/15-content_filter_mode
		echo "@bypass_virus_checks_maps = (" /etc/amavis/conf.d/15-content_filter_mode
		echo " \%bypass_virus_checks, \@bypass_virus_checks_acl, \$bypass_virus_checks_re);" /etc/amavis/conf.d/15-content_filter_mode
		echo "@bypass_spam_checks_maps = (" /etc/amavis/conf.d/15-content_filter_mode
		echo " \%bypass_spam_checks, \@bypass_spam_checks_acl, \$bypass_spam_checks_re);" /etc/amavis/conf.d/15-content_filter_mode
		echo "1;"
		AMAVISC="/etc/amavis/conf.d/50-user"
		echo "use strict;" > $AMAVISC
		echo "@local_domains_acl = qw(.);" >> $AMAVISC
		echo "\$log_level = 2;" >> $AMAVISC	# Change to 1 to reduce login details
		echo "\$syslog_priority = 'debug';" >> $AMAVISC # Change to 'info' to reduce login details
		echo "# \$sa_tag_level_deflt = 2.0; # add spam info headers if at, or above that level" >> $AMAVISC
		echo "# \$sa_tag2_level_deflt = 6.31; # add 'spam detected' headers at that level" >> $AMAVISC
		echo "\$sa_kill_level_deflt = 8.0; # triggers spam evasive actions" >> $AMAVISC
		echo "# \$sa_dsn_cutoff_level = 10; # spam level beyond which a DSN is not sent" >> $AMAVISC
		echo "# \$final_spam_destiny = D_PASS;" >> $AMAVISC
		echo "# \$final_spam_destiny = D_REJECT; # default " >> $AMAVISC
		echo "\$final_spam_destiny = D_BOUNCE; # debian default " >> $AMAVISC # Change to D_DISCARD when things were going well
		echo "# \$final_spam_destiny = D_DISCARD; # ubuntu default, recommended as sender is usually faked" >> $AMAVISC
		echo "1;" >> $AMAVISC
		if ! grep -q "smtp-amavis" $PANEL_PATH/configs/postfix/master.cf ; then
			echo "smtp-amavis      unix    -       -       -       -       2       smtp" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtp_data_done_timeout=1200" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtp_send_xforward_command=yes" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o disable_dns_lookups=yes" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o max_use=20" >> $PANEL_PATH/configs/postfix/master.cf
			echo "" >> $PANEL_PATH/configs/postfix/master.cf
			echo "127.0.0.1:10025 inet    n       -       -       -       -       smtpd" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o content_filter=" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o local_recipient_maps=" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o relay_recipient_maps=" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_restriction_classes=" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_delay_reject=no" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_client_restrictions=permit_mynetworks,reject" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_helo_restrictions=" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_sender_restrictions=" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_recipient_restrictions=permit_mynetworks,reject" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_data_restrictions=reject_unauth_pipelining" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_end_of_data_restrictions=" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o mynetworks=127.0.0.0/8" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_error_sleep_time=0" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_soft_error_limit=1001" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_hard_error_limit=1000" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_client_connection_count_limit=0" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o smtpd_client_connection_rate_limit=0" >> $PANEL_PATH/configs/postfix/master.cf
			echo "        -o receive_override_options=no_header_body_checks,no_unknown_recipient_checks" >> $PANEL_PATH/configs/postfix/master.cf
			sed -i "s@pickup@pickup	  fifo	n	-	-	60	1	pickup\n\t-o content_filter=\n\t-o receive_override_options=no_header_body_checks\n#@" $PANEL_PATH/configs/postfix/master.cf
			echo "content_filter = smtp-amavis:[127.0.0.1]:10024" >> $PANEL_PATH/configs/postfix/main.cf
		fi
		change "-R" "775" amavis amavis /var/lib/amavis/tmp
		# Order of restarting following services are relevant in some contexts
		service postfix restart
		service opendkim restart
		service spamassassin restart
		service clamav-daemon restart
		service clamav-freshclam restart
		/etc/init.d/amavis restart
	fi
fi

#====================================================================================
#--- Dovecot
echo -e "\n-- Dovecot security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		# backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/dovecot/sentora ] ; then
			echo "Dovecot config files already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/dovecot/sentora
			cp -v $PANEL_PATH/configs/dovecot2/dovecot.conf $SENTORA_PARANOID_BACKUP_PATH/dovecot/sentora
		fi
		# Log more authentication info (the correct place for this is conf.d/10-auth.conf but senotra does not include configs for some reason)
		if ! grep -q "auth_verbose" $PANEL_PATH/configs/dovecot2/dovecot.conf ; then
			echo "auth_verbose = yes" >> $PANEL_PATH/configs/dovecot2/dovecot.conf			
			echo "auth_debug = yes" >> $PANEL_PATH/configs/dovecot2/dovecot.conf			
		fi
		# File permissions
		change "-R" "g+w" root $ADMIN_GRP /etc/dovecot/conf.d
		change "-R" "g+w" root $ADMIN_GRP $PANEL_PATH/configs/dovecot2
		change "" "g-w" root root $PANEL_PATH/configs/dovecot2
		service dovecot restart
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		# restore from backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/dovecot/sentora/dovecot ] ; then
			cp -v $SENTORA_PARANOID_BACKUP_PATH/dovecot/sentora/dovecot.conf $PANEL_PATH/configs/dovecot2
		else
			echo "Original dovecot config files unchanged"
		fi
		# File permissions
		change "-R" "g-w" root root /etc/dovecot/conf.d
		change "" "g-w" root $ADMIN_GRP $PANEL_PATH/configs/dovecot2/*.conf
		service dovecot restart
	fi
fi

#====================================================================================
#--- PHP
echo -e "\n-- PHP security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		# backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/php5 ] ; then
			echo "PHP config file already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/php5/{apache2,cli}
			cp -v /etc/php5/apache2/php.ini $SENTORA_PARANOID_BACKUP_PATH/php5/apache2
			cp -v /etc/php5/cli/php.ini $SENTORA_PARANOID_BACKUP_PATH/php5/cli
		fi
		
		# Now adjust php configurations in both apache2/php.ini and cli/php.ini
		# (many of them has correct values by default, but we aro not going to make any assumptions)

		# Disable insecure functions 
		sed -i "s@disable_functions =.*@disable_functions = system,exec,eval,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority@" /etc/php5/apache2/php.ini
		sed -i "s@disable_functions =.*@disable_functions = system,exec,eval,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority@" /etc/php5/cli/php.ini
		echo "NOTICE: Functions [system, exec and eval] are disabled, this may cause conflicts whit some php scripts"
		# Do not expose php installed (web only)
		sed -i "s@expose_php = On@expose_php = Off@" /etc/php5/apache2/php.ini
		# Reduce error reporting in production web server
		sed -i 's/error_reporting =.*/error_reporting = E_ALL \& \~E_DEPRECATED/' /etc/php5/apache2/php.ini
		sed -i "s@display_errors = On@display_errors = Off@" /etc/php5/apache2/php.ini
		sed -i "s@display_startup_errors = On@display_startup_errors = Off@" /etc/php5/apache2/php.ini
		sed -i "s@track_errors = On@track_errors = Off@" /etc/php5/apache2/php.ini
		sed -i "s@html_errors = On@html_errors = Off@" /etc/php5/apache2/php.ini
		echo "NOTICE: PHP error reporting has been reduced for production environment"
		# Reduce error reporting in system console		
		sed -i "s@error_reporting =.*@error_reporting = E_ALL \& \~E_DEPRECATED \& \~E_NOTICE@" /etc/php5/cli/php.ini
		sed -i "s@display_errors = On@display_errors = Off@" /etc/php5/cli/php.ini
		sed -i "s@display_startup_errors = On@display_startup_errors = Off@" /etc/php5/cli/php.ini
		sed -i "s@track_errors = On@track_errors = Off@" /etc/php5/cli/php.ini
		sed -i "s@html_errors = On@html_errors = Off@" /etc/php5/cli/php.ini
		# Prevent code injection (web only)
		sed -i "s@allow_url_fopen = On@allow_url_fopen = Off@" /etc/php5/apache2/php.ini
		sed -i "s@allow_url_include = On@allow_url_include = Off@" /etc/php5/apache2/php.ini
		echo "NOTICE: Remote url fopen/include are disabled, this may cause conflicts whit some php scripts"
		# File permissions
		change "" "g+w" root $ADMIN_GRP /etc/php5/apache2/php.ini
		change "" "g+w" root $ADMIN_GRP /etc/php5/cli/php.ini
	else
		echo -e "$OS $VER not tested, PHP5 security not performed\n"		
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		# restore from backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/php5 ] ; then
			cp -v $SENTORA_PARANOID_BACKUP_PATH/php5/apache2/php.ini /etc/php5/apache2/php.ini
			cp -v $SENTORA_PARANOID_BACKUP_PATH/php5/cli/php.ini /etc/php5/cli/php.ini
		else
			echo "Original PHP5 config file unchanged"
		fi
		# File permissions
		change "" "g-w" root root /etc/php5/apache2/php.ini
		change "" "g-w" root root /etc/php5/cli/php.ini
	else
		echo -e "$OS $VER not tested, PHP5 security not reverted\n"		
	fi
fi

#====================================================================================
#--- suphp must/should be (re)enabled with sentora environment?
# To be revised and may be included in future versions
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
	 true
	fi
fi


#====================================================================================
#--- Phpmyadmin
echo -e "\n-- Phpmyadmin security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		true
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		true
	fi
fi

#====================================================================================
#--- Roundcube
echo -e "\n-- Roundcube security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		# backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/roundcube/sentora ] ; then
			echo "Roundcube config file already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/roundcube/sentora
			cp -v $PANEL_PATH/configs/roundcube/roundcube_config.inc.php $SENTORA_PARANOID_BACKUP_PATH/roundcube/sentora
			cp -v $PANEL_PATH/configs/roundcube/sieve_config.inc.php $SENTORA_PARANOID_BACKUP_PATH/roundcube/sentora
		fi
		# Enable authentication error log and disable installer
		#sed -i "s@\['log_session'\] = false@\['log_session'\] = true@" $PANEL_PATH/configs/roundcube/main.inc.php
		#sed -i "s@\['enable_installer'\] = true@\['enable_installer'\] = false@" $PANEL_PATH/configs/roundcube/main.inc.php
		if ! grep -q "# sentora-paranoid" $PANEL_PATH/configs/roundcube/roundcube_config.inc.php ; then
			echo "$config['log_session'] = false;" >> $PANEL_PATH/configs/roundcube/roundcube_config.inc.php
			echo "$config['enable_installer'] = false;" >> $PANEL_PATH/configs/roundcube/roundcube_config.inc.php
		fi
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		# restore from backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/roundcube/sentora ] ; then
			cp -v $SENTORA_PARANOID_BACKUP_PATH/roundcube/sentora/main.inc.php $PANEL_PATH/configs/roundcube
		else
			echo "Original apache security config file unchanged"
		fi
	fi
fi

#====================================================================================
#--- webalyzer
echo -e "\n-- Webalyzer security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		true
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		true
	fi
fi

#====================================================================================
#--- Modsecurity must/should be (re)enabled with sentora environment?
# To be revised and include in future versions
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
	 true
	fi
fi

#====================================================================================
#--- Apache
echo -e "\n-- Apache security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		# backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/apache2 ] ; then
			echo "Apache security & sentora config file already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/apache2/{conf-available,sentora}
			cp -v $PANEL_PATH/configs/apache/httpd.conf $SENTORA_PARANOID_BACKUP_PATH/apache2/sentora
			cp -v /etc/apache2/conf-available/other-vhosts-access-log.conf $SENTORA_PARANOID_BACKUP_PATH/apache2/conf-available
			rm -fv /etc/apache2/conf-enabled/other-vhosts-access-log.conf
			mv -v /etc/apache2/conf-available/other-vhosts-access-log.conf /etc/apache2/conf-available/other-vhosts-log.conf
			ln -svf ../conf-available/other-vhosts-log.conf /etc/apache2/conf-enabled/other-vhosts-log.conf
			cp -v /etc/apache2/conf-available/security.conf $SENTORA_PARANOID_BACKUP_PATH/apache2/conf-available
		fi
		# remove security config override in sentora/httpd.conf, the rigth place is security.conf
		sed -i "s@ServerTokens Prod@#ServerTokens Prod@g" $PANEL_PATH/configs/apache/httpd.conf
		# Add host(ing) signature
		if ! grep -q "Header set X-Hosting" $PANEL_PATH/configs/apache/httpd.conf; then
			echo "Header set X-Hosting \"$FQDN\"" >> $PANEL_PATH/configs/apache/httpd.conf
		fi
		# The default error log file is ${APACHE_LOG_DIR}/error.log, is better to split vhost error log from apache2 errors,
		# we can write failure rules related to vhosts only
		if ! grep -q "ErrorLog" /etc/apache2/conf-available/other-vhosts-log.conf ; then
			echo "ErrorLog \${APACHE_LOG_DIR}/other_vhosts_error.log" >> /etc/apache2/conf-available/other-vhosts-log.conf
			touch /var/log/apache2/other_vhosts_error.log
		fi
		# change security config
		sed -i "s@ServerTokens OS@ServerTokens Prod@g" /etc/apache2/conf-available/security.conf
		sed -i "s@ServerSignature On@ServerSignature Off@g" /etc/apache2/conf-available/security.conf
		sed -i "s@TraceEnable On@TraceEnable Off@g" /etc/apache2/conf-available/security.conf
		# ...not sure if removing ETag enhances security
		#Header unset ETag
		#FileETag None
		
		# File permissions
		change "" "g+w" root $ADMIN_GRP /etc/apache2/apache2.conf
		change "" "g+w" root $ADMIN_GRP /etc/apache2/ports.conf*
		change "-R" "g+w" root $ADMIN_GRP /etc/apache2/conf-available
		change "-R" "g+w" root $ADMIN_GRP /etc/apache2/conf-enabled
		change "-R" "g+w" root $ADMIN_GRP /etc/apache2/sites-available
		change "" "g+w" root $ADMIN_GRP /etc/apache2/sites-enabled
		change "" "640" root adm /var/log/apache2/other_vhosts_error.log
		# Ensure administrator user belongs to adm group
		GRP=$(groups $ADMIN_USR | grep "\badm\b")
		if [ -z "$GRP" ]; then
			usermod -a -G adm $ADMIN_USR
			echo "Adding $ADMIN_USR to adm group"
			echo "ADMGRP:true" >> $datfile
		fi
		# Add user ADMIN_USR to HTTP_GROUP
		GRP=$(groups $ADMIN_USR | grep $HTTP_GROUP)
		if [ -z "$GRP" ]; then
			usermod -a -G $HTTP_GROUP $ADMIN_USR
			echo "Adding $ADMIN_USR to apache group"
		fi
		# Enable secure socket layer module and restart service
		a2enmod ssl
		a2enmod headers
		service apache2 restart
	else
		echo -e "$OS $VER not tested, apache security not performed\n"
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		# restore from backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/apache2 ] ; then
			cp -v $SENTORA_PARANOID_BACKUP_PATH/apache2/sentora/httpd.conf $PANEL_PATH/configs/apache
			cp -v $SENTORA_PARANOID_BACKUP_PATH/apache2/conf-available/other-vhosts-access-log.conf /etc/apache2/conf-available
			rm -vf /etc/apache2/conf-enabled/other-vhosts-log.conf
			rm -vf /etc/apache2/conf-available/other-vhosts-log.conf
			ln -svf ../conf-available/other-vhosts-access-log.conf /etc/apache2/conf-enabled/other-vhosts-access-log.conf
			cp -v $SENTORA_PARANOID_BACKUP_PATH/apache2/conf-available/security.conf  /etc/apache2/conf-available/security.conf
			rm -vf /var/log/apache2/other_vhosts_error.log
		else
			echo "Original apache security config file unchanged"
		fi
		# File permissions
		change "" "g-w" root root /etc/apache2/apache2.conf
		change "" "g-w" root root /etc/apache2/ports.conf*
		change "-R" "g-w" root root /etc/apache2/conf-available
		change "-R" "g-w" root root /etc/apache2/conf-enabled
		change "-R" "g-w" root root /etc/apache2/sites-available
		change "" "g-w" root root /etc/apache2/sites-enabled
		# Remove administrator user from adm group if we added only
		ADMGRP=$(grep "ADMGRP" $datfile | sed "s@ADMGRP:@@")
		# Remove administrator user from HTTP_GROUP
		GRP_WWW=$(groups $ADMIN_USR | grep $HTTP_GROUP)
		if [ -n "$GRP_WWW" ]; then
			if [ -n "$ADMGRP" ] ; then
				GRP_LST=$(id -nG $ADMIN_USR | sed "s@\badm\b @@" | sed "s@$HTTP_GROUP @@" | sed "s@ @,@g")
			else
				GRP_LST=$(id -nG $ADMIN_USR | sed "s@$HTTP_GROUP @@" | sed "s@ @,@g")
			fi
			usermod -G $GRP_LST $ADMIN_USR
			echo "Removing $ADMIN_USR from (adm and) apache group and leaving original groups: $GRP_LST"
		fi
		# Disable secure socket layer module and restart service
		a2dismod ssl
		a2dismod headers
		service apache2 restart
	else
		echo -e "$OS $VER not tested, apache security not reverted\n"		
	fi
fi

#====================================================================================
#--- ProFTPd + SFTPd
echo -e "\n-- Proftpd security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		# backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/proftpd/sentora ] ; then
			echo "ProFTPd config file already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/proftpd/sentora
			cp -v $PANEL_PATH/configs/proftpd/proftpd-mysql.conf $SENTORA_PARANOID_BACKUP_PATH/proftpd/sentora
			touch /var/sentora/logs/proftpd/auth.log
			touch /var/sentora/logs/proftpd/sftp.log
		fi
		# We are not sure if the administrator email exists and if it is necesary to change this email use next command
		# sed -i "s/root@localhost/$ADMIN_USR@$FQDN/" $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
		# Enable sftp
		if ! grep -q "LoadModule mod_sftp.c" $PANEL_PATH/configs/proftpd/proftpd-mysql.conf ; then
			echo "NOTICE: sftp enabled to listen in default port 115"
			echo "LoadModule mod_sftp.c" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "<IfModule mod_sftp.c>" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "  <VirtualHost $local_ip>" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		SFTPEngine on" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		Port 115" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		SFTPLog $PANEL_DATA/logs/proftpd/sftp.log" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		# Configure both the RSA and DSA host keys, using the same host key" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		# files that OpenSSH uses." >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		SFTPHostKey /etc/ssh/ssh_host_rsa_key" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		SFTPHostKey /etc/ssh/ssh_host_dsa_key" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		#SFTPAuthMethods publickey" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		#SFTPAuthorizedUserKeys file:$PANEL_PATH/configs/proftpd/authorized_keys/%u" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		SFTPAuthMethods password" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		# Enable compression" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "		SFTPCompression delayed" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "  </VirtualHost>" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
			echo "</IfModule>" >> $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
		fi
		# File permissions
		change "" "g+w" root $ADMIN_GRP $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
		change "-R" "g+w" root $ADMIN_GRP /etc/proftpd/conf.d
		change "" "g+w" root $ADMIN_GRP /etc/proftpd/*.conf
		service proftpd restart
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		# restore from backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/proftpd/sentora ] ; then
			cp -v $SENTORA_PARANOID_BACKUP_PATH/proftpd/sentora/proftpd-mysql.conf $PANEL_PATH/configs/proftpd
			#rm -vf /var/sentora/logs/proftpd/auth.log
			rm -vf /var/sentora/logs/proftpd/sftp.log
		else
			echo "Original proftpd config file unchanged"
		fi
		change "" "g-w" root root $PANEL_PATH/configs/proftpd/proftpd-mysql.conf
		change "-R" "g-w" root root /etc/proftpd/conf.d		
		change "" "g-w" root root /etc/proftpd/*.conf
		service proftpd restart
	fi
fi

#====================================================================================
#--- Bind
echo -e "\n-- Bind security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		# backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/bind ] ; then
			echo "Bind config file already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/bind
			cp -v /etc/bind/named.conf $SENTORA_PARANOID_BACKUP_PATH/bind
		fi
		# Public IP is trusted but localhost too
		sed -i "s@acl trusted-servers {@acl trusted-servers {\n\tlocalhost;@" /etc/bind/named.conf
		# Ensure there is no recursion and write additional security config
		sed -i "s@recursion yes;@recursion no;@g" /etc/bind/named.conf
		sed -i "s@recursion no;@recursion no;\n\tedns-udp-size 4096;\n\tmanaged-keys-directory \"/var/named/dynamic\";\n\tversion \"[hidden]\";@g" /etc/bind/named.conf
		# File permissions
		change "" "g+w" root $ADMIN_GRP /etc/bind/named.conf
		change "-R" "g+w" root bind $PANEL_DATA/logs/bind
		named-checkconf /etc/bind/named.conf
		service bind9 restart
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		# restore from backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/bind ] ; then
			cp -v $SENTORA_PARANOID_BACKUP_PATH/bind/named.conf /etc/bind
		else
			echo "Original bind config file unchanged"
		fi
		# File permissions
		change "" "g-w" root bind /etc/bind/named.conf
		change "-R" "a+w" $HTTP_USER $HTTP_USER $PANEL_DATA/logs/bind
		named-checkconf /etc/bind/named.conf
		service bind9 restart
	fi
fi

#====================================================================================
#--- cron/atd
echo -e "\n-- Cron / atd security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		true
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		true
	fi
fi

#====================================================================================
#--- ipset
echo -e "\n-- ipset security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
	 	ipset destroy BLACKLIST_IP -q
		ipset create BLACKLIST_IP hash:ip hashsize 2048 -q
		ipset flush BLACKLIST_IP
		ipset destroy BLACKLIST_NET -q
		ipset create BLACKLIST_NET hash:net hashsize 1024 -q
		ipset flush BLACKLIST_NET
		ipset add BLACKLIST_IP 176.31.61.1
		ipset add BLACKLIST_NET 176.31.61.0/28
		echo "NOTICE: ipset blacklists are set, this may block legitimate IPs"
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		ipset flush BLACKLIST_IP -q
		ipset flush BLACKLIST_NET -q
	fi
fi

#====================================================================================
#--- Enabling firewall
echo -e "\n-- Setting basic firewall rules"
echo "NOTICE: Allowing ssh port number: $SSHD_PORT in firewall and closing all other ssh ports"
# Check for better firewall rules availability
if [ -d $SENTORA_PARANOID_CONFIG_PATH/iptables ] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		iptables-restore < $SENTORA_PARANOID_CONFIG_PATH/iptables/iptables.firewall.rules
		ip6tables-restore < $SENTORA_PARANOID_CONFIG_PATH/iptables/ip6tables.firewall.rules
	else
		echo -e "$COLOR_YLW WARNING: Firewall not (re)started in this OS. $COLOR_END\n"	
	fi
else
	# Rules are deleted (called revert more than once?), so set basic (sentora required) rules
	# ipv4
	if [ -n "$iptables_version" ] ; then
		iptables --flush
		echo "Set ipv4 firewall with very basic rules"
		iptables -A INPUT -i lo -j ACCEPT
		iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT
		iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
		iptables -A OUTPUT -j ACCEPT
		iptables -A INPUT -m state --state INVALID -j DROP
		iptables -A INPUT -p tcp --dport 21 -j ACCEPT
		iptables -A INPUT -p tcp --dport 53 -j ACCEPT
		iptables -A INPUT -p udp --dport 53 -j ACCEPT
		iptables -A INPUT -p tcp --dport 80 -j ACCEPT
		iptables -A INPUT -p tcp --dport 443 -j ACCEPT
		iptables -A INPUT -p tcp --dport 25 -j ACCEPT
		iptables -A INPUT -p tcp --dport 465 -j ACCEPT
		iptables -A INPUT -p tcp --dport 110 -j ACCEPT
		iptables -A INPUT -p tcp --dport 995 -j ACCEPT
		iptables -A INPUT -p tcp -m state --state NEW --dport $SSHD_PORT -j ACCEPT
		iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT --match limit --limit 30/minute
		iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "sentora-paranoid ip4 denied: " --log-level 7
		iptables -A INPUT -j REJECT
		iptables -A FORWARD -j REJECT
	fi
	# ipv6
	if [ -n "$ip6tables_version" ] ; then
		ip6tables --flush
		echo "Set ipv6 firewall with very basic rules"
		ip6tables -A INPUT -s ::1 -d ::1 -j ACCEPT
		ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
		ip6tables -A OUTPUT -j ACCEPT
		ip6tables -A INPUT -m state --state INVALID -j DROP
		ip6tables -A INPUT -i eth0 -p ipv6 -j ACCEPT 
		ip6tables -A OUTPUT -o eth0 -p ipv6 -j ACCEPT 
		ip6tables -A INPUT -p tcp --dport 21 -j ACCEPT
		ip6tables -A INPUT -p tcp --dport 53 -j ACCEPT
		ip6tables -A INPUT -p udp --dport 53 -j ACCEPT
		ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
		ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
		ip6tables -A INPUT -p tcp --dport 25 -j ACCEPT
		ip6tables -A INPUT -p tcp --dport 465 -j ACCEPT
		ip6tables -A INPUT -p tcp --dport 110 -j ACCEPT
		ip6tables -A INPUT -p tcp --dport 995 -j ACCEPT
		ip6tables -A INPUT -p tcp -m state --state NEW --dport $SSHD_PORT -j ACCEPT
		ip6tables -A INPUT -p icmpv6 -j ACCEPT
		ip6tables -A FORWARD -j REJECT --reject-with icmp6-adm-prohibited
		ip6tables -A INPUT --protocol icmpv6 --icmpv6-type echo-request -j ACCEPT --match limit --limit 30/minute
		ip6tables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "sentora-paranoid ip6 denied: " --log-level 7
		ip6tables -A INPUT -j REJECT
		ip6tables -A FORWARD -j REJECT
	fi
fi

# Save persistant rules
if [[ "$OS" = "Ubuntu" ]]; then
	if [ ! -d /etc/iptables ] ; then
		mkdir -vp /etc/iptables
	fi
	iptables-save > /etc/iptables/rules.v4
	ip6tables-save > /etc/iptables/rules.v6
fi

#====================================================================================
#--- Fail2ban
# [TO-DO] filter.d/roundcube filter regexp
echo -e "\n-- Fail2ban security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		# backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/fail2ban/filter.d ] ; then
			echo "file2ban config files already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/fail2ban/filter.d
			cp -v /etc/fail2ban/jail.* $SENTORA_PARANOID_BACKUP_PATH/fail2ban
			cp -v /etc/fail2ban/filter.d/* $SENTORA_PARANOID_BACKUP_PATH/fail2ban/filter.d
			cp -v $SENTORA_PARANOID_CONFIG_PATH/fail2ban/filter.d/* /etc/fail2ban/filter.d
			mkdir -vp $PANEL_DATA/logs/domains/_default
			ln -s  /var/log/apache2/other_vhosts_error.log $PANEL_DATA/logs/domains/_default/error.log
			mkdir -vp $PANEL_DATA/logs/roundcube
			touch $PANEL_DATA/logs/roundcube/sessions
		fi
		# Set localip
		sed -i "s@%%LOCAL_IP%%@$local_ip@g" $SENTORA_PARANOID_CONFIG_PATH/fail2ban/jail.local
		cp -v $SENTORA_PARANOID_CONFIG_PATH/fail2ban/jail.local /etc/fail2ban
		/etc/init.d/fail2ban restart
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		# restore from backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/fail2ban/filter.d ] ; then
			cp -v $SENTORA_PARANOID_BACKUP_PATH/fail2ban/jail.* /etc/fail2ban
			cp -v $SENTORA_PARANOID_BACKUP_PATH/fail2ban/filter.d/* /etc/fail2ban/filter.d
			rm -rvf $PANEL_DATA/logs/domains/_default
			rm -rvf $PANEL_DATA/logs/roundcube
		else
			echo "Original fail2ban configs file unchanged"
		fi
		/etc/init.d/fail2ban restart
	fi
fi

#====================================================================================
#--- AppArmor
# for use aparmor with vhosts see mod_apparmor at http://wiki.apparmor.net/index.php/Mod_apparmor_example
# [TO-DO] modify default sentora vhost file writer to confine scripts (something like open_basedir and suhosin.executor.func.whitelist or blacklist)
echo -e "\n-- AppArmor security"
if [[ "$REVERT" = "false" ]] ; then
	if [[ "$OS" = "Ubuntu" ]]; then
		# backup
		if [ -d $SENTORA_PARANOID_BACKUP_PATH/apparmor.d ] ; then
			echo "apparmor profiles already backed up"
		else
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/apparmor.d
			cp -vr /etc/apparmor.d/* $SENTORA_PARANOID_BACKUP_PATH/apparmor.d
			# apache sentora config file backedup by apache
			mkdir -vp $SENTORA_PARANOID_BACKUP_PATH/panel/modules/apache_admin/hooks
			cp -vr $PANEL_PATH/panel/modules/apache_admin/hooks/OnDaemonRun.hook.php $SENTORA_PARANOID_BACKUP_PATH/panel/modules/apache_admin/hooks/OnDaemonRun.hook.php
		fi
		update-rc.d apparmor defaults
		rm -v /etc/apparmor.d/disable/usr.sbin.apache2
		cp -v $SENTORA_PARANOID_CONFIG_PATH/apparmor.d/usr.sbin.named /etc/apparmor.d
		cp -v $SENTORA_PARANOID_CONFIG_PATH/apparmor.d/apache2.d/* /etc/apparmor.d/apache2.d
		change "-R" "g+w" root $APACHE_GRP /etc/apparmor.d/apache2.d
		aa-complain /etc/apparmor.d/*
		sed -i "s@<Directory /etc/sentora/panel>@<Directory /etc/sentora/panel>\n\tAAHatName sentora@" $PANEL_PATH/configs/apache/httpd.conf
		sed -i 's@"  AllowOverride All" . fs_filehandler::NewLine()@"  AllowOverride All" . fs_filehandler::NewLine() . "  AAHatName vhost" . fs_filehandler::NewLine()@g' $PANEL_PATH/panel/modules/apache_admin/hooks/OnDaemonRun.hook.php
		a2enmod mpm_prefork
		a2enmod apparmor
		service apache2 restart
		service apparmor start
	fi
else
	if [[ "$OS" = "Ubuntu" ]]; then
		# restore from backup
		if [ $SENTORA_PARANOID_BACKUP_PATH/apparmor.d ] ; then
			cp -vr $SENTORA_PARANOID_BACKUP_PATH/apparmor.d /etc/apparmor.d
			# apache sentora config file restored by apache
			cp -vr $SENTORA_PARANOID_BACKUP_PATH/panel/modules/apache_admin/hooks/OnDaemonRun.hook.php $PANEL_PATH/panel/modules/apache_admin/hooks/OnDaemonRun.hook.php
			ln -svf /etc/apparmor.d/usr.sbin.apache2 /etc/apparmor.d/disable
		else
			echo "Original apparmor profiles unchanged"
		fi
		# is safe to disable mod_prefork?
		a2dismod apparmor
		service apache2 restart
		service apparmor stop
	fi
fi

#====================================================================================
#--- If revert remove sentora-paranoid preconf directory from site
if [[ "$REVERT" = "false" ]] ; then
	true
else
	echo -e "\n-- Removing sentora-paranoid preconf directory"
	if [ -d $SENTORA_PARANOID_CONFIG_PATH ] ; then
		rm -rvf $SENTORA_PARANOID_CONFIG_PATH
	fi
fi

if [[ "$STORE_TREE" = "true" ]] ; then
	# Store final file permissions
	echo "Storing final file permissions"
	if [ -f sentora-paranoid-$$.2nd ] ; then
		truncate -s 0 sentora-paranoid-$$.2nd
	fi
	save_tree /etc/sentora 2nd
	save_tree /etc/mysql 2nd
	save_tree /etc/postfix 2nd
	save_tree /etc/php5 2nd
	save_tree /etc/apache2 2nd
	save_tree /etc/dovecot 2nd
	save_tree /etc/proftpd 2nd
	save_tree /etc/bind 2nd
	save_tree /etc/fail2ban 2nd
	save_tree /etc/apparmor.d 2nd
fi

# Check if all services are running
echo -e "\n-- Checking services status"
if [[ "$OS" = "Ubuntu" ]]; then
	check_status
fi

CURRENT_DIR=$(pwd)
echo "#########################################################"
if [[ "$REVERT" = "false" ]] ; then
	#--- Advise the admin that Sentora is now installed and accessible.
	echo " Congratulations sentora-paranoid has now been installed "
	echo " on your server. Please review the log file for any error"
	echo " encountered during installation."
	echo ""
	echo " Log file is located at:"
	echo " $CURRENT_DIR/$logfile"
	if [[ "$STORE_TREE" = "true" ]] ; then
		echo " Tree files are located at: $CURRENT_DIR"
	fi
	echo ""
	echo " MySQL: paranoid user pasword is: $PP"
	echo ""
	echo " For relevant information about security changes please"
	echo " take a look for the NOTICE messages in log file or using"
	echo " the following command:"
	echo "  grep \"NOTICE\" $CURRENT_DIR/$logfile"
	echo ""
else
	#--- Advise the admin that Sentora is now uninstalled
	echo " Congratulations sentora-paranoid has now been uninstalled"
	echo ""
	echo " Log file is located at:"
	echo " $CURRENT_DIR/$logfile"
fi
echo "#########################################################"
echo ""

# Wait until the user have read before restarts the server...
if [[ "$OS" = "Ubuntu" ]]; then
    while true; do
        read -e -p "Restart your server now to complete the install (Y/n)? " -i 'y' answer
        case $answer in
            [Yy]* ) break;;
            [Nn]* ) exit;
        esac
    done
    shutdown -r now
fi

# [TO DO] Review http://www.cyberciti.biz/tips/linux-security.html
#				http://security-24-7.com/hardening-guide-for-postfix-2-x/