#!/usr/bin/env bash

# 1. download the list of cipher suites
# 2. format the JSON in order for (git) diff to better work
# 3. save the file to `recon/analyzers/tls/cipher_suites.json`


# find location of `cipher_suites.json`
target=$(
  find $HOME -iwholename '*/analyzers/tls/cipher_suites.json' |
  head --lines 1
)

curl --silent https://ciphersuite.info/api/cs/ |
  jq . > "$target"
