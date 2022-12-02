#!/usr/bin/awk -f
# parse and analyze web server response headers
# https://csp-evaluator.withgoogle.com/

# invoke this program like this:
# /path/to/this/file /path/to/recon/*/services/http*nmap.log

# function to append a value to an array, if that array does not yet contain the value
function append_to_array(array, value) {
  for (i in array) {
    if (value == array[i])
      return
  }
  array[length(array)+1] = value
}

BEGINFILE {
  host = ""
  
  x_frame_options = "missing"
  csp = "missing"
  hsts = "missing"
  x_content_type_options = "missing"
  referrer_policy = "missing"

  state = ""
}

/^# Nmap .+ scan initiated/ {
  host = $NF
  next
}

/tcp open/ && /http/ {
  split($0, ports, "/")
  port = ports[1]

  schema = $3

  if (schema ~ /ssl/) {
    schema = "https"
  }

  if (schema == "http") {
    hsts = "this header should not be present!"
  }

  printf "\n## %s://%s:%s\n\n", schema, host, port

  state = "port"
  next
}

# this line is the opener of the `http-headers` script
/\|.http-headers:/ {
  state = "http-headers"
}

# each script's output is terminated with '|_'
(state == "http-headers") && /\|_/ {
  nextfile
}

(state != "http-headers") {
  next
}

tolower($0) ~ /x-frame-options:/ {
  sub(/^\| +/, "", $0)
  x_frame_options = $0

  if ($0 !~ /DENY/ && $0 !~ /SAMEORIGIN/) {
    printf "* misconfigured: `%s`\n", $0
    append_to_array(hosts, host)
  }
  
  next
}

tolower($0) ~ /x-xss-protection:/ && ! /0/ {
  sub(/^\| +/, "", $0)
  printf "* misconfigured: `%s`\n", $0
  append_to_array(hosts, host)
  next
}

tolower($0) ~ /content-security-policy:/ {
  sub(/^\| +/, "", $0)
  csp = $0

  #content-security-policy: script-src 'self' 'unsafe-inline' 'unsafe-eval';style-src 'self' 'unsafe-inline' data:;img-src 'self' data:;font-src 'self' data:;form-action 'self';frame-ancestors 'self';block-all-mixed-content

  value = substr($0, 26)
  #print value

  split(value, directives, ";")

  script_src = "missing"
  object_src = "missing"

  for (i in directives) {
    dir = directives[i]
    gsub(/^[ \t]+/, "", dir)

    if (dir ~ /script-src/) {
      script_src = dir
      if (dir ~ /unsafe-inline/) {
        printf "* misconfigured CSP: `script-src 'unsafe-inline'` allows the execution of unsafe in-page scripts and event handlers\n"
        append_to_array(hosts, host)
      }
      if (dir ~ /unsafe-eval/) {
        printf "* misconfigured CSP: `script-src 'unsafe-eval'` allows the execution of code injected into DOM APIs such as `eval()`\n"
        append_to_array(hosts, host)
      }
    }

    if (dir ~ /object-src/) {
      object_src = dir
      if (dir !~ /none/) {
        printf "* misconfigured CSP: `%s`\n", dir
        append_to_array(hosts, host)
      }
    }
  }

  if (script_src == "missing") {
    printf "* misconfigured CSP: missing `script-src` directive\n"
    append_to_array(hosts, host)
  }

  if (object_src == "missing") {
    printf "* misconfigured CSP: missing `object-src` directive allows the injection of plugins which can execute JavaScript; you should set it to `none`\n"
    append_to_array(hosts, host)
  }

  next
}

tolower($0) ~ /strict-transport-security:/ {
  if (schema == "http") {
    # https://datatracker.ietf.org/doc/html/rfc6797#section-7.2
    printf "* misconfigured STS: an HSTS host must not include the STS header field in responses conveyed over non-secure transport (i.e. HTTP)\n"
    append_to_array(hosts, host)
  }

  sub(/^\| +/, "", $0)
  hsts = $0

  if ($0 !~ /max-age=63072000/) {
    printf "* misconfigured: `%s`\n", $0
    append_to_array(hosts, host)
  }

  next
}

tolower($0) ~ /x-content-type-options:/ {
  sub(/^\| +/, "", $0)
  x_content_type_options = $0

  if ($0 !~ /nosniff/) {
    printf "* misconfigured: `%s`\n", $0
    append_to_array(hosts, host)
  }

  next
}

tolower($0) ~ /referrer-policy:/ {
  sub(/^\| +/, "", $0)
  referrer_policy = $0

  if ($0 ~ /unsafe-url/) {
    printf "* misconfigured: `%s`\n", $0
    append_to_array(hosts, host)
  }

  next
}

ENDFILE {
  if (host) {
    if (state != "http-headers") {
      printf "error analysing file: no HTTP headers found\n"
    } else {
      if (x_frame_options == "missing") {
        printf "* missing `X-Frame-Options` header\n"
        append_to_array(hosts, host)
      }

      if (csp == "missing") {
        printf "* missing `Content-Security-Policy` header\n"
        append_to_array(hosts, host)
      }

      if (hsts == "missing") {
        printf "* missing `Strict-Transport-Security` header\n"
        append_to_array(hosts, host)
      }

      if (x_content_type_options == "missing") {
        printf "* missing `X-Content-Type-Options` header\n"
        append_to_array(hosts, host)
      }

      if (referrer_policy == "missing") {
        printf "* missing `Referrer-Policy` header\n"
        append_to_array(hosts, host)
      }
    }
  }
}

END {
  printf "\n# affected assets\n\n"
  for (i in hosts) {
    printf "* `%s`\n", hosts[i]
  }
}
