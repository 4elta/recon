#!/usr/bin/awk -f
# parse TCP/UDP port scans and list online hosts.

# invoke this program like this:
# /path/to/script /path/to/nmap/ports*.nmap

# function to append a value to an array, if that array does not yet contain the value
function append_to_array(array, value) {
  for (i in array) {
    if (value == array[i])
      return
  }
  array[length(array)+1] = value
}

BEGINFILE {
  hosts = ""
}

/^Nmap scan report for / {
  host = $5
  next
}

(host == "") {
  next
}

# only look for 'open' ports, ignore 'open|filtered' ports.
# https://nmap.org/book/man-port-scanning-basics.html
$2 == "open" {
  append_to_array(hosts, host)
}

END {
  for (i in hosts) {
    printf "%s\n", hosts[i]
  }
}
