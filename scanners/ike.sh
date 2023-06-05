#!/usr/bin/env bash

# this scrip tries to enumerate specific (problematic) transform attributes (i.e. encryption/hash algorithm, authentication method, etc) for IKEv1 servers.
# at the end, it also tries to establish an IKEv2 handshake with the server.
# it utilizes [`ike-scan`](https://github.com/royhills/ike-scan).

# [TR-02102-3](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-3.html) is used as a guideline (even though it covers IKEv2)

SOURCE_PORT=500
# 0: use a random UDP source port; default=500
# some IKE implementations require the client to use UDP source port 500 and will not talk to other ports.
# superuser privileges are normally required to use non-zero source ports below 1024.

if [ "$SOURCE_PORT" -lt 1024 ] && [ "$EUID" -ne 0 ]; then
  echo "this script has to be run as the root user!" 1>&2
  exit 1
fi

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
  #"3" # Tiger, https://en.wikipedia.org/wiki/Tiger_(hash_function)
)

# authentication methods:
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-8
AUTHENTICATION_METHODS=(
  "1" # pre-shared key
  "2" # DSS signatures
  "3" # RSA signatures
  "4" # encryption with RSA
  "64221" # HybridInitRSA, https://datatracker.ietf.org/doc/html/draft-zegman-ike-hybrid-auth#section-3.2.1
  "65001" # XAUTHInitPreShared, https://datatracker.ietf.org/doc/html/draft-beaulieu-ike-xauth-02#section-7.2
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
  echo "Usage: $(basename $0) <target>" 1>&2
  exit 1
fi

target="$1"
dport="${2:-500}"

# IKEv1

for encryption_algorithm in "${ENCRYPTION_ALGORITHMS[@]}"; do
  for hash_algorithm in ${HASH_ALGORITHMS[@]}; do
    for authentication_method in ${AUTHENTICATION_METHODS[@]}; do
      for dh_group in ${DH_GROUPS[@]}; do
        if [ "$dport" -eq "4500" ]; then
          printf "\nike-scan --nat-t --trans='%s,%s,%s,%s' %s\n" ${encryption_algorithm} ${hash_algorithm} ${authentication_method} ${dh_group} ${target}
          result=$(
            ike-scan \
              --nat-t \
              --trans="${encryption_algorithm},${hash_algorithm},${authentication_method},${dh_group}" \
              ${target} \
            | grep 'Handshake returned'
          )

          if [ ! -z "$result" ]; then
            echo "$result"
            printf "\nike-scan --nat-t --trans='%s,%s,%s,%s' --aggressive --dhgroup='%s' --id=test %s\n" ${encryption_algorithm} ${hash_algorithm} ${authentication_method} ${dh_group} ${dh_group} ${target}

            ike-scan \
              --nat-t \
              --trans="${encryption_algorithm},${hash_algorithm},${authentication_method},${dh_group}" \
              --aggressive --dhgroup=${dh_group} --id=test \
              ${target} \
            | grep 'Handshake returned'
          fi
        else
          printf "\nike-scan --dport=%d --trans='%s,%s,%s,%s' %s\n" ${dport} ${encryption_algorithm} ${hash_algorithm} ${authentication_method} ${dh_group} ${target}
          result=$(
            ike-scan \
              --dport=${dport} \
              --trans="${encryption_algorithm},${hash_algorithm},${authentication_method},${dh_group}" \
              ${target} \
            | grep 'Handshake returned'
          )

          if [ ! -z "$result" ]; then
            echo "$result"
            printf "\nike-scan --dport=%d --trans='%s,%s,%s,%s' --aggressive --dhgroup='%s' --id=test %s\n" ${dport} ${encryption_algorithm} ${hash_algorithm} ${authentication_method} ${dh_group} ${dh_group} ${target}

            ike-scan \
              --dport=${dport} \
              --trans="${encryption_algorithm},${hash_algorithm},${authentication_method},${dh_group}" \
              --aggressive --dhgroup=${dh_group} --id=test \
              ${target} \
            | grep 'Handshake returned'
          fi
        fi
      done
    done
  done
done

# IKEv2

# this delay seems to be necessary, as otherwise the last scan would not succeed
sleep 5

if [ "$dport" -eq "4500" ]; then
  printf "\nike-scan --nat-t --ikev2 %s\n" ${target}
  ike-scan --nat-t --ikev2 ${target} | grep 'Handshake returned'
else
  printf "\nike-scan --dport=%d --ikev2 %s\n" ${dport} ${target}
  ike-scan --dport=${dport} --ikev2 ${target} | grep 'Handshake returned'
fi
