# in case Nmap has misidentified certain services,
# this script lets you correct this.

# run it like this:
# awk -v 'r=<host>:<protocol>:<port>:<service>:<new service>' \
#     -f /path/to/this/script.awk \
#     /path/to/services.xml

# to not filter on a particular aspect (i.e. host, protocol, port, service),
# provide the name of the aspect as the filter.
# for example: to correct the service identification on *all* hosts,
# use the following replacement rule: 'r=host:<protocol>:...'.

BEGIN {
  if (r == "") {
    print "please specify replacement:\n-v 'r=<host>:<protocol>:<port>:<service>:<new service>'"
    exit
  }

  split(r, tokens, ":")
  host = tokens[1]
  protocol = tokens[2]
  port = tokens[3]
  service = tokens[4]
  new_service = tokens[5]
}

/<host>/ {
  matched_host = ""
}

(/<address addr="[^"]+"/ || /<hostname name="[^"]+"/) && $0 ~ host {
  matched_host = host
}

matched_host == host && /<port protocol="[^"]+" portid="[^"]+">/ && \
$0 ~ protocol && $0 ~ port && $0 ~ service {
  gsub(/<service name="[^"]+"/, "<service name=\"" new_service "\"")
  print
  next
}

{
  print
}
