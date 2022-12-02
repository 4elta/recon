#!/usr/bin/awk -f
# parse and analyze ike-scan results (i.e. icke_ike.sh)

# invoke this program like this:
# /path/to/this/file /path/to/recon/*/services/*-icke_ike.log

# function to append a value to an array,
# if that array does not yet contain the value
function append_to_array(array, value) {
  for (i in array) {
    if (value == array[i])
      return
  }
  array[length(array)+1] = value
}

BEGINFILE {
  delete enc
  delete hash
  delete auth
  delete group
  delete key_length
}

/^# target:/ {
  host = $3
  printf "\n## %s\n\n", host
  append_to_array(hosts, host)
  next
}

# look for "Aggressive Mode"
/Aggressive Mode/ {
  aggressive = "true"
}

# look for lines of the form "key=value"
/^[^= ]+=/ {
  split($0, parts, "=")
  value = parts[2]
}

/^Enc=/ {
  append_to_array(enc, value)
  next
}

/^Hash=/ {
  append_to_array(hash, value)
  next
}

/^Auth=/ {
  append_to_array(auth, value)
  next
}

/^Group=/ {
  append_to_array(group, value)
  next
}

/^KeyLength=/ {
  append_to_array(key_length, value)
  next
}

ENDFILE {
  if (aggressive == "true") {
    printf "* supports \"aggressive mode\"\n"
  }

  printf "* offered encryption algorithms:\n"
  for (i in enc) {
    printf "  * `%s`\n", enc[i]
  }

  printf "* offered hash algorithms:\n"
  for (i in hash) {
    printf "  * `%s`\n", hash[i]
  }

  printf "* offered authentication algorithms:\n"
  for (i in auth) {
    printf "  * `%s`\n", auth[i]
  }

  printf "* offered DH groups:\n"
  for (i in group) {
    printf "  * `%s`\n", group[i]
  }

  printf "* offered key lengths:\n"
  for (i in key_length) {
    printf "  * %s\n", key_length[i]
  }
}

END {
  printf "\n# affected assets\n\n"
  for (i in hosts) {
    printf "* `%s`\n", hosts[i]
  }
}
