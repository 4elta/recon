#!/usr/bin/awk -f
# analyze TLS configuration

# invoke this program like this:
# /path/to/this/file /path/to/recon/*/services/*-sslyze.log

# function to print only the reason of a specific compliance failure
function print_reason() {
  # replace the single quote (') with a backtick (`)
  gsub(/'/, "`")
  # remove the curly braces ({, })
  gsub(/({|})/, "")

  printf "*"
  for (i = 3; i <= NF; i++) printf FS$i;
  printf "\n"
}

BEGIN {
  configuration = "intermediate"
  state = ""
}

/Checking results against Mozilla's "(modern|intermediate|old)" configuration/ {
  state = "compliance"

  match($0, /(modern|intermediate|old)/)
  configuration = substr($0, RSTART, RLENGTH)

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
  printf "\n\n**%s** (configuration: %s)\n\n", host, configuration
  
  next
}

!/^$/ {
  print_reason()
  next
}

ENDFILE {
  state = ""
}
