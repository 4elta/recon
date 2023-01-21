#!/usr/bin/awk -f
# analyze TLS configuration based on Mozilla's configuration
# https://wiki.mozilla.org/Security/Server_Side_TLS
# https://github.com/nabla-c0d3/sslyze/blob/release/sslyze/mozilla_tls_profile/mozilla_config_checker.py

# invoke this program like this:
# /path/to/this/file /path/to/recon/*/services/*-sslyze.log

# function to append a value to an array, if that array does not yet contain the value
function append_to_array(array, value) {
  for (i in array) {
    if (value == array[i])
      return
  }
  array[length(array)+1] = value
}

# function to convert the UNIX epoch into ISO date/time format
function iso_date(epoch) {
  cmd = "date --date='@" epoch "' --iso-8601=seconds"
  cmd | getline date_time
  close(cmd)

  return date_time
}

# function to change single quotes into backticks
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
  # get the current date/time in seconds since the UNIX epoch
  cmd = "date \"+%s\""
  cmd | getline current_datetime

  # look-ahead time for expiring certificates
  look_ahead_days = 30
  look_ahead_time = look_ahead_days * 24 * 60 * 60

  # Mozilla configuration
  configuration = "intermediate"
  state = ""
}

# get host
/SCAN RESULTS FOR / {
  match($0, /SCAN RESULTS FOR ([^:]+):([0-9]+) -/, matches)
  host = matches[1]
  port = matches[2]

  printf "\n\n## %s:%d\n\n", host, port
  next
}

# the server could present more than one certificate; get the certificate number
/Certificate #[0-9]+ / {
  match($0, /#([0-9]+) /, matches)
  certificate_nr = matches[1]
  next
}

# is the certificate valid?
/Not Before: / || /Not After: / {
  # Not Before:      1970-01-01
  # 1   2            3
  
  # convert the date/time string into the number of seconds since the UNIX epoch
  cmd = "date --date='" $3 "' \"+%s\""
  cmd | getline datetime
  close(cmd)

  if ($2 == "Before:" && current_datetime <= datetime) {
    printf "* certificate #%d will only be valid after %s\n", certificate_nr, iso_date(datetime)
    append_to_array(hosts, host)
  }

  if ($2 == "After:") {
    if (current_datetime >= datetime) {
      printf "* certificate #%d expired since %s\n", certificate_nr, iso_date(datetime)
      append_to_array(hosts, host)
    } else if (current_datetime + look_ahead_time >= datetime) {
      printf "* certificate #%d expires in %s days or less (%s)\n", certificate_nr, look_ahead_days, iso_date(datetime)
      append_to_array(hosts, host)
    }
  }

  next
}

# is the certificate self signed?
/Mozilla CA Store/ && /self signed/ {
  printf "* certificate #%d not trusted: self signed\n", certificate_nr
  append_to_array(hosts, host)
  next
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
  append_to_array(hosts, host)
  printf "\nDeviations from Mozilla's \"%s\" configuration:\n\n", configuration
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
  printf "* RSA key size: %s\n", matches[1]
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

END {
  printf "\n# affected assets\n\n"
  for (i in hosts) {
    printf "* `%s`\n", hosts[i]
  }
}
