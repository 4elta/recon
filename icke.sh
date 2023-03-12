#!/usr/bin/env bash

# "icke bin berliner!"

# this scrip tries to verify whether an IKEv1 server supports specific (problematic) transform attributes (i.e. encryption/hash algorithm, authentication method, etc).
# it utilizes [`ike-scan`](https://github.com/royhills/ike-scan).

# [TR-02102-3](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-3.html) is used as a guideline (even though it covers IKEv2)

# encryption algorithms:
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-4
ENCRYPTION_ALGORITHMS=(
  "1" # DES-CBC
  "2" # IDEA-CBC
  "4" # RC5-R16-B64-CBC
  "5" # 3DES-CBC
  "6" # CAST-CBC
  "7/128" # AES-CBC/128
  "7/192" # AES-CBC/192
  "7/256" # AES-CBC/256
)

# hash algorithms:
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-6
HASH_ALGORITHMS=(
  "1" # MD5
  "2" # SHA
)

# authentication methods:
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-8
AUTHENTICATION_METHODS=(
  "1" # pre-shared key
  "2" # DSS signatures
  "3" # RSA signatures
  "4" # encryption with RSA
  "64221" # HybridInitRSA, https://datatracker.ietf.org/doc/html/draft-zegman-ike-hybrid-auth#section-3.2.1
  "65001" # HybridInitRSA, https://datatracker.ietf.org/doc/html/draft-beaulieu-ike-xauth-02#section-7.2
)

# Diffie-Hellman group descriptions
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-10
DH_GROUPS=(
  "1" # 768-bit MODP
  "2" # alternate 1024-bit MODP
  "5" # 1536-bit MODP
  "14" # 2048-bit MODP
  "22" # 1024-bit MODP with 160-bit Prime Order Subgroup
  "23" # 2048-bit MODP with 224-bit Prime Order Subgroup
  "24" # 2048-bit MODP with 256-bit Prime Order Subgroup
)

if [ -z "$1" ]; then
  echo "Usage: $(basename $0) <target>"
  exit 1
fi

target="$1"

echo "# target: $target"

for encryption_algorithm in "${ENCRYPTION_ALGORITHMS[@]}"; do
  for hash_algorithm in ${HASH_ALGORITHMS[@]}; do
    for authentication_method in ${AUTHENTICATION_METHODS[@]}; do
      for dh_group in ${DH_GROUPS[@]}; do
        result=$(ike-scan --trans="${encryption_algorithm},${hash_algorithm},${authentication_method},${dh_group}" --multiline $target | awk '/Handshake returned/')
        if [ ! -z "$result" ]; then
          printf '\n# ike-scan -a "%s,%s,%s,%s" -M %s\n' "$encryption_algorithm" "$hash_algorithm" "$authentication_method" "$dh_group" "$target"
          echo $result

          # determine whether the VPN server supports *aggressive* mode
          # https://nvd.nist.gov/vuln/detail/CVE-2002-1623
          # https://raxis.com/blog/2018/05/23/ike-vpns-supporting-aggressive-mode/
          result=$(ike-scan --aggressive --id=test --trans="${encryption_algorithm},${hash_algorithm},${authentication_method},${dh_group}" --multiline $target | awk '/Handshake returned/')
          if [ ! -z "$result" ]; then
            printf '\n# ike-scan -A -n test -a "%s,%s,%s,%s" -M %s\n' "$encryption_algorithm" "$hash_algorithm" "$authentication_method" "$dh_group" "$target"
            echo $result
          fi
        fi
      done
    done
  done
done
