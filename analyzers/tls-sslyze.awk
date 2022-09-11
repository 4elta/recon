#!/usr/bin/awk -f
# analyze TLS configuration based on Mozilla's configuration
# https://wiki.mozilla.org/Security/Server_Side_TLS
# https://github.com/nabla-c0d3/sslyze/blob/release/sslyze/mozilla_tls_profile/mozilla_config_checker.py

# invoke this program like this:
# /path/to/this/file /path/to/recon/*/services/*-sslyze.log

function backtick(field) {
  gsub("'", "`", field)
  return field
}

function print_items(matches) {
  n = split(matches, items, ", ")
  asort(items, sorted_items)
  for (i = 1; i <= n; i++) {
    printf "  * %s\n", backtick(sorted_items[i])
  }
}

BEGIN {
  configuration = "intermediate"
  state = ""
}

/Checking results against Mozilla's "(modern|intermediate|old)" configuration/ {
  state = "compliance"

  match($0, /(modern|intermediate|old)/, matches)
  configuration = matches[1]

  next
}

(state != "compliance") {
  next
}

/OK - Compliant/ {
  state = ""
  nextfile
}

/[^:]+:[0-9]+: FAILED - Not compliant.$/ {
  host = substr($1, 1, length($1) - 1)
  printf "\n\n#### %s\n\nDeviations from Mozilla's \"%s\" configuration:\n\n", host, configuration
  next
}

/tls_curves:/ {
  printf "* TLS curve(s):\n"
  match($0, /curves \{([^\}]+)\}/, matches)
  print_items(matches[1])
  next
}

/tls_vulnerability_compression:/ {
  printf "* vulnerable to TLS compression attacks\n"
  next
}

/tls_vulnerability_heartbleed:/ {
  printf "* vulnerable to the OpenSSL Heartbleed attack\n"
  next
}

/tls_vulnerability_robot:/ {
  printf "* vulnerable to the ROBOT attack\n"
  next
}

/tls_vulnerability_renegotiation:/ {
  printf "* vulnerable to the insecure renegotiation attack\n"
  next
}

/certificate_hostname_validation:/ {
  match($0, /validation failed for ([^\.]+)\./, matches)
  printf "* certificate hostname validation failed for `%s`\n", matches[1]
  next
}

/certificate_path_validation:/ {
  match($0, /validation failed for ([^\.]+)\./, matches)
  printf "* certificate path validation failed for `%s`\n", matches[1]
  next
}

/certificate_curves:/ {
  printf "* certificate curve(s):\n"
  match($0, /curve is \{([^\}]+)\}/, matches)
  print_items(matches[1])
  next
}

/rsa_key_size:/ {
  match($0, /key size is ([0-9]+)/, matches)
  printf "* RSA key size: %s\n"
  next
}

/maximum_certificate_lifespan:/ {
  match($0, /([0-9]+ days)/, matches)
  printf "* certificate lifespan: %s\n", matches[1]
  next
}

/certificate_types:/ {
  printf "* certificate type(s):\n"
  match($0, /types are \{([^}]+)\}/, matches)
  print_items(matches[1])
  next
}

/certificate_signatures:/ {
  printf "* certificate signature algorithm(s):\n"
  match($0, /signatures are \{([^}]+)\}/, matches)
  print_items(matches[1])
  next
}

/tls_versions:/ {
  printf "* TLS version(s):\n"
  match($0, /versions \{([^}]+)\}/, matches)
  print_items(matches[1])
  next
}

/ciphersuites:/ {
  printf "* TLS 1.3 cipher suite(s):\n"
  match($0, /suites \{([^}]+)\}/, matches)
  print_items(matches[1])
  next
}

/ciphers:/ {
  printf "* cipher suite(s):\n"
  match($0, /suites \{([^}]+)\}/, matches)
  print_items(matches[1])
  next
}

/ecdh_param_size:/ {
  match($0, /parameter size is ([0-9]+)/, matches)
  printf "* ECDH parameter size: %s\n", matches[1]
  next
}

/dh_param_size:/ {
  match($0, /parameter size is ([0-9]+)/, matches)
  printf "* DH parameter size: %s\n", matches[1]
  next
}

ENDFILE {
  state = ""
}
