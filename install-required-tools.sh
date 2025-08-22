#!/usr/bin/env bash

# unofficial bash strict mode
set -euo pipefail
IFS=$'\n\t'

# load environment variables (i.e. 'ID' and 'ID_LIKE')
source /etc/os-release

package_manager="apt"
ID_LIKE=${ID_LIKE:-$ID}
if [ "$ID_LIKE" == "arch" ]; then
  package_manager="pacman"
fi

if [ "$package_manager" == "apt" ]; then
  sudo apt update
  sudo apt install --yes \
    curl \
    dnsutils \
    ike-scan \
    nfs-common \
    nmap \
    python3-defusedxml \
    python3-dnspython \
    python3-impacket \
    python3-jinja2 \
    rpcbind \
    smbclient \
    testssl.sh \
    whatweb
elif [ "$package_manager" == "pacman" ]; then
  sudo pacman -Syu
  sudo pacman -S --needed --noconfirm \
    curl \
    bind \
    ike-scan \
    nfs-common \
    nmap \
    python-defusedxml \
    python-dnspython \
    impacket \
    python-jinja \
    rpcbind \
    smbclient \
    testssl \
    whatweb
fi

tools_directory=${1:-"$HOME/tools"}
mkdir --parents "$tools_directory"
cd "$tools_directory"

# Nikto
# "Install (recommended): Run from a git repo"
# --https://cirt.net/Nikto2

nikto=$(command -v "nikto") || true
if [ -z "$nikto" ]; then
  if [ "$package_manager" == "apt" ]; then
    sudo apt install --yes libnet-ssleay-perl
  elif [ "$package_manager" == "pacman" ]; then
    sudo pacman -S --needed --noconfirm perl-net-ssleay
  fi

  [ ! -d "nikto" ] && git clone --depth 1 https://github.com/sullo/nikto.git || true

  file_path="/usr/local/bin/nikto"
  [ -f "$file_path" ] && sudo rm "$file_path" || true
  sudo ln --symbolic "$(realpath nikto/program/nikto.pl)" "$file_path"
fi

# enum4linux-ng

enum4linux_ng=$(command -v "enum4linux-ng") || true
if [ -z "$enum4linux_ng" ]; then
  if [ "$ID" == "kali" ]; then
    sudo apt install --yes enum4linux-ng
  elif [ "$ID" == "blackarch" ]; then
    sudo pacman -S --needed --noconfirm enum4linux-ng
  else
    if [ "$package_manager" == "apt" ]; then
      sudo apt install --yes \
        python3-impacket \
        python3-ldap3 \
        python3-yaml \
        smbclient
    elif [ "$package_manager" == "pacman" ]; then
      sudo pacman -S --needed --noconfirm \
        impacket \
        python-ldap3 \
        python-yaml \
        smbclient
    fi

    [ ! -d "enum4linux-ng" ] && git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git || true

    file_path="/usr/local/bin/enum4linux-ng"
    [ -f "$file_path" ] && sudo rm "$file_path" || true
    sudo ln --symbolic "$(realpath enum4linux-ng/enum4linux-ng.py)" "$file_path"
  fi
fi

# SecLists

file_path="/usr/share/seclists"
if [ ! -d "$file_path" ]; then
  if [ "$ID" == "kali" ]; then
    sudo apt install --yes seclists
  elif [ "$ID" == "blackarch" ]; then
    sudo pacman -S --needed --noconfirm seclists
  else
    [ ! -d "SecLists" ] && git clone --depth 1 https://github.com/danielmiessler/SecLists.git || true
    sudo ln --symbolic "$(realpath SecLists)" "$file_path"
  fi
fi

# SIPVicious

if [ "$package_manager" == "apt" ]; then
  sudo apt install --yes sipvicious
elif [ "$ID" == "blackarch" ]; then
  sudo pacman -S --needed --noconfirm sipvicious
else
  [ ! -d "sipvicious" ] && git clone --depth 1 https://github.com/enablesecurity/sipvicious.git || true
  cd sipvicious
  python3 setup.py install
fi
