#!/usr/bin/env bash

# "icke bin berliner!"

# this scrip tries to verify whether an IKE server supports specific (problematic) transform attributes (i.e. encryption/hash algorithm, authentication method, etc).
# it utilizes [`ike-scan`](https://github.com/royhills/ike-scan)

if [ -z "$1" ]; then
  echo "Usage: $(basename $0) <target>"
  exit 1
fi

target="$1"

# encryption algorithms: DES-CBC, 3DES-CBC, AES-CBC/128, AES-CBC/192 and AES-CBC/256
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-4
ENCRYPTION_ALGORITHMS="1 5 7/128 7/192 7/256"

# hash algorithms: MD5 and SHA
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-6
HASH_ALGORITHMS="1 2"

# authentication methods: pre-shared key, RSA signatures, HybridInitRSA and XAUTHInitPreShared
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-8
# see https://datatracker.ietf.org/doc/html/draft-zegman-ike-hybrid-auth#section-3.2.1
# see https://datatracker.ietf.org/doc/html/draft-beaulieu-ike-xauth-02#section-7.2
AUTHENTICATION_METHODS="1 3 64221 65001"

# Diffie-Hellman group descriptions: 768-bit MODP, alternate 1024-bit MODP and 1536-bit MODP
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-10
DH_GROUPS="1 2 5"

function parse_result {
  local result="$1"
  echo "$result" | sed -E 's|^.+(Enc=[^ ]+).+$|\1|'
  echo "$result" | sed -E 's|^.+(Hash=[^ ]+).+$|\1|'
  echo "$result" | sed -E 's|^.+(Auth=[^ ]+).+$|\1|'
  echo "$result" | sed -E 's|^.+(Group=[^ ]+).+$|\1|'
  (echo "$result" | grep -q 'KeyLength=') && echo "$result" | sed -E 's|^.+(KeyLength=[^ ]+).+$|\1|'
}

echo "# target: $target"

for encryption_algorithm in $ENCRYPTION_ALGORITHMS; do
  for hash_algorithm in $HASH_ALGORITHMS; do
    for authentication_method in $AUTHENTICATION_METHODS; do
      for dh_group in $DH_GROUPS; do
        result=$(ike-scan --trans="${encryption_algorithm},${hash_algorithm},${authentication_method},${dh_group}" $target | awk '/Handshake returned/')
        if [ ! -z "$result" ]; then
          printf '\n# ike-scan --trans="%s,%s,%s,%s" %s\n' "$encryption_algorithm" "$hash_algorithm" "$authentication_method" "$dh_group" "$target"
          echo $result
          parse_result "$result"

          # determine whether the VPN server supports *aggressive* mode
          result=$(ike-scan --aggressive --id=test --trans="${encryption_algorithm},${hash_algorithm},${authentication_method},${dh_group}" $target | awk '/Handshake returned/')
          if [ ! -z "$result" ]; then
            printf '\n# ike-scan --aggressive --id=test --trans="%s,%s,%s,%s" %s\n' "$encryption_algorithm" "$hash_algorithm" "$authentication_method" "$dh_group" "$target"
            echo $result
            parse_result "$result"
          fi
        fi
      done
    done
  done
done
