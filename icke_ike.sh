#!/usr/bin/env bash

# "icke bin berliner!"

if [ -z "$1" ]; then
  echo "Usage: $(basename $0) <target>"
  exit 1
fi

target="$1"

# Encryption algorithms: DES, Triple-DES, AES/128, AES/192 and AES/256
ENCLIST="1 5 7/128 7/192 7/256"

# Hash algorithms: MD5 and SHA1
HASHLIST="1 2"

# Authentication methods: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH
AUTHLIST="1 3 64221 65001"

# Diffie-Hellman groups: 1, 2 and 5
GROUPLIST="1 2 5"

function parse_result {
  local result="$1"
  echo "$result" | sed -E 's|^.+(Enc=[^ ]+).+$|\1|'
  echo "$result" | sed -E 's|^.+(Hash=[^ ]+).+$|\1|'
  echo "$result" | sed -E 's|^.+(Auth=[^ ]+).+$|\1|'
  echo "$result" | sed -E 's|^.+(Group=[^ ]+).+$|\1|'
  (echo "$result" | grep -q 'KeyLength=') && echo "$result" | sed -E 's|^.+(KeyLength=[^ ]+).+$|\1|'
}

echo "# target: $target"

for ENC in $ENCLIST; do
  for HASH in $HASHLIST; do
    for AUTH in $AUTHLIST; do
      for GROUP in $GROUPLIST; do
        result=$(ike-scan --trans="${ENC},${HASH},${AUTH},${GROUP}" $target | awk '/Handshake returned/')
        if [ ! -z "$result" ]; then
          printf '\n# ike-scan --trans="%s,%s,%s,%s" %s\n' "$ENC" "$HASH" "$AUTH" "$GROUP" "$target"
          echo $result
          parse_result "$result"

          result=$(ike-scan -A -id=test --trans="${ENC},${HASH},${AUTH},${GROUP}" $target | awk '/Handshake returned/')
          if [ ! -z "$result" ]; then
            printf '\n# ike-scan -A -id=test --trans="%s,%s,%s,%s" %s\n' "$ENC" "$HASH" "$AUTH" "$GROUP" "$target"
            echo $result
            parse_result "$result"
          fi
        fi
      done
    done
  done
done
