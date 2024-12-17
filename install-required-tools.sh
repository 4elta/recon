#!/usr/bin/env bash

# unofficial bash strict mode
set -euo pipefail
IFS=$'\n\t'

sudo apt update
sudo apt install --yes \
  curl \
  dnsutils \
  ike-scan \
  nmap \
  onesixtyone \
  python3-dnspython \
  python3-impacket \
  smbclient \
  snmp \
  testssl.sh \
  whatweb

tools_directory=${1:-"$HOME/tools"}
mkdir --parents "$tools_directory"
cd "$tools_directory"

# Nikto
# "Install (recommended): Run from a git repo"
# --https://cirt.net/Nikto2

sudo apt install --yes libnet-ssleay-perl
git clone --depth 1 https://github.com/sullo/nikto.git
sudo ln --symbolic $(realpath nikto/program/nikto.pl) /usr/local/bin/nikto

if grep --quiet "^Kali" /etc/issue; then
  sudo apt install --yes \
    enum4linux-ng \
    seclists
else
  # enum4linux-ng

  sudo apt install --yes \
    python3-impacket \
    python3-ldap3 \
    python3-yaml \
    smbclient

  git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git
  sudo ln --symbolic $(realpath enum4linux-ng/enum4linux-ng.py) /usr/local/bin/enum4linux-ng

  # SecLists

  git clone --depth 1 https://github.com/danielmiessler/SecLists.git
  sudo ln --symbolic $(realpath SecLists) /usr/share/seclists
fi
