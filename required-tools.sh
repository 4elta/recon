#!/usr/bin/env bash

# script to install and update required tools via package manager if possible,
# otherwise from GitHub to $TOOLS_DIRECTORY.

# unofficial bash strict mode
set -euo pipefail
IFS=$'\n\t'

TOOLS_DIRECTORY="${HOME}/tools"
mkdir --parents "$TOOLS_DIRECTORY"
cd "$TOOLS_DIRECTORY"

# load environment variables (i.e. 'ID' and 'ID_LIKE')
source /etc/os-release

PACKAGE_MANAGER="apt"
ID_LIKE=${ID_LIKE:-$ID}
[[ "$ID_LIKE" == "arch" ]] && PACKAGE_MANAGER="pacman" || true

if [[ "$PACKAGE_MANAGER" != "apt" && "$PACKAGE_MANAGER" != "packman" ]]; then
  printf "this script currently only works on Debian- and Arch-based distributions.\n"
  printf "please create an issue at github.com/4elta/recon if you would like to add support for other distributions."
  exit 1
fi

usage() {
  echo "usage: $0 <install|update>"
}

get_latest_release_string() {
  local author=$1
  local project=$2

  curl --silent --head \
    "https://github.com/${author}/${project}/releases/latest" |
  grep --extended-regexp '^location: ' |
  sed --regexp-extended 's|^location: .+/tag/([[:alnum:].]+)[[:space:]]*$|\1|'
}

install_latest_release_github_source() {
  local author=$1
  local project=$2
  local release=$(get_latest_release_string $author $project)

  # check if the latest release has already been downloaded
  [[ -f "$TOOLS_DIRECTORY/${project}-${release}.zip" ]] && return 0 || true

  printf "downloading from GitHub: %s/%s (%s) ...\n" $author $project $release
  curl --output "${project}-${release}.zip" --silent \
    "https://codeload.github.com/${author}/${project}/zip/refs/tags/${release}"

  mkdir --parents "${TOOLS_DIRECTORY}/${project}"

  [[ -d "$project" ]] && rm --recursive "$project" || true

  printf "extracting ...\n"
  unzip -q ${project}-${release}.zip
  rm ${project}-*.zip

  # for some projects the unzipped source directory contains a 'v' in front of the release string.
  # i.e.: '{project}-v{release}'

  mkdir --parents $project
  mv ${project}-*/* $project || true
  rm --recursive ${project}-*

  touch ${project}-${release}.zip
}

install_nikto() {
  # "Install (recommended): Run from a git repo"
  # --https://cirt.net/Nikto2

  local target=$1

  printf "installing enum4linux-ng ...\n"
  # https://github.com/sullo/nikto

  printf "installing requirements ...\n"
  # https://github.com/sullo/nikto/wiki/Install-Unix
  if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
    sudo apt install --yes libnet-ssleay-perl
  elif [[ "$PACKAGE_MANAGER" == "pacman" ]]; then
    sudo pacman -S --needed --noconfirm perl-net-ssleay
  fi

  install_latest_release_github_source "sullo" "nikto"

  if [[ -f "$target" ]]; then
    printf "creating symbolic link '%s' ...\n" "$target"
    sudo ln --symbolic "${TOOLS_DIRECTORY}/nikto/program/nikto.pl" "$target"
  fi
}

install_enum4linux_ng() {
  local target=$1

  printf "installing enum4linux-ng ...\n"

  if [[ "$ID" == "kali" ]]; then
    sudo apt install --yes enum4linux-ng
  elif [[ "$ID" == "blackarch" ]]; then
    sudo pacman -S --needed --noconfirm enum4linux-ng
  else
    # https://github.com/cddmp/enum4linux-ng

    printf "installing requirements ...\n"
    if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
      sudo apt install --yes \
        python3-impacket \
        python3-ldap3 \
        python3-yaml \
        smbclient
    elif [[ "$PACKAGE_MANAGER" == "pacman" ]]; then
      sudo pacman -S --needed --noconfirm \
        impacket \
        python-ldap3 \
        python-yaml \
        smbclient
    fi

    install_latest_release_github_source "cddmp" "enum4linux-ng"

    if [[ ! -f "$target" ]]; then
      printf "creating symbolic link '%s' ...\n" "$target"
      sudo ln --symbolic "${TOOLS_DIRECTORY}/enum4linux-ng/enum4linux-ng.py" "$target"
    fi
  fi
}

install_seclists() {
  local target=$1

  printf "installing SecLists ...\n"

  # make sure the target is not a directory, because then it's already installed via package manager
  [[ -d "$target" ]] && return 0 || true

  if [ "$ID" == "kali" ]; then
    sudo apt install --yes seclists
  elif [ "$ID" == "blackarch" ]; then
    sudo pacman -S --needed --noconfirm seclists
  else
    # https://github.com/danielmiessler/SecLists
    install_latest_release_github_source "danielmiessler" "SecLists"

    if [ ! -f "$target" ]; then
      printf "creating symbolic link '%s' ...\n" "$target"
      sudo ln --symbolic "${TOOLS_DIRECTORY}/SecLists" "$target"
    fi
  fi
}

install_sipvicious() {
  printf "installing SIPVicious ...\n"

  if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
    sudo apt install --yes sipvicious
  elif [[ "$ID" == "blackarch" ]]; then
    sudo pacman -S --needed --noconfirm sipvicious
  else
    # https://github.com/EnableSecurity/sipvicious
    install_latest_release_github_source "enablesecurity" "sipvicious"
    sipvicious/setup.py install
  fi
}

install_latest_release_github_rmg() {
  local target="/usr/local/bin/rmg"
  local author="qtc-de"
  local project="remote-method-guesser"
  local release=$(get_latest_release_string $author $project | sed 's:^v::')

  # check if the latest release has already been downloaded
  [[ -f "rmg-${release}.jar" ]] && return 0 || true

  # deleting old releases of RMG
  ls rmg-*.jar &> /dev/null && rm rmg-*.jar || true

  printf "downloading from GitHub: %s/%s (%s) ...\n" $author $project $release
  curl --output "rmg-${release}.jar" --location --silent \
    "https://github.com/${author}/${project}/releases/download/v${release}/rmg-${release}-jar-with-dependencies.jar"

  # updating run script
  cat > rmg << EOF
#!/usr/bin/sh
exec java -jar "${TOOLS_DIRECTORY}/rmg-${release}*.jar" "\$@"
EOF

  chmod +x rmg
  if [ ! -f "$target" ]; then
    printf "creating symbolic link '%s' ...\n" "$target"
    sudo ln --symbolic "${TOOLS_DIRECTORY}/rmg" "$target"
  fi
}

install_rmg() {
  printf "installing Remote Method Guesser ...\n"

  if [[ "$ID" == "blackarch" ]]; then
    # https://github.com/BlackArch/blackarch/packages/remote-method-guesser/PKGBUILD
    sudo pacman -S --needed --noconfirm remote-method-guesser
  else
    # https://github.com/qtc-de/remote-method-guesser

    printf "installing requirements ...\n"
    if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
      sudo apt install --yes \
        default-jre-headless
    elif [[ "$PACKAGE_MANAGER" == "pacman" ]]; then
      sudo pacman -S --needed --noconfirm \
        jre-openjdk-headless
    fi

    install_latest_release_github_rmg
  fi
}

install_tools() {
  if [ "$PACKAGE_MANAGER" == "apt" ]; then
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
  elif [ "$PACKAGE_MANAGER" == "pacman" ]; then
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

  command -v "nikto" >/dev/null && install_nikto "/usr/local/bin/nikto" || true
  command -v "enum4linux-ng" >/dev/null && install_enum4linux_ng "/usr/local/bin/enum4linux-ng" || true
  install_seclists "/usr/share/seclists"
  command -v "svmap" >/dev/null && install_sipvicious || true
  command -v "rmg" >/dev/null && install_rmg || true
}

update_tools() {
  install_latest_release_github_source "sullo" "nikto" || true

  if [[ "$ID" != "kali" && "$ID" != "blackarch" ]]; then
    install_latest_release_github_source "cddmp" "enum4linux-ng"
    install_latest_release_github_source "danielmiessler" "SecLists"
  fi

  if [[ "$PACKAGE_MANAGER" != "apt" && "$ID" != "blackarch" ]]; then
    install_latest_release_github_source "enablesecurity" "sipvicious"
    sipvicious/setup.py install
  fi

  if [[ "$ID" != "blackarch" ]]; then
    install_latest_release_github_rmg
  fi
}

# make sure the user provided an operation mode
if [[ "$#" != 1 ]]; then
  usage
  exit 1
fi

if [[ $1 == "install" ]]; then
  printf "installing required tools ...\n"
  install_tools
elif [[ $1 == "update" ]]; then
  printf "updating tools ...\n"
  update_tools
else
  usage
  exit 1
fi
