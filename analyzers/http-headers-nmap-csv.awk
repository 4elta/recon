#!/usr/bin/awk -f
# analyze web server response headers; output CSV
# https://csp-evaluator.withgoogle.com/

# invoke this program like this:
# /path/to/this/file /path/to/recon/*/services/http*nmap.log

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

  service = schema "://" host ":" port

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
    printf "%s,misconfigured: `%s`\n", service, $0
  }

  next
}

tolower($0) ~ /x-xss-protection:/ && ! /0/ {
  sub(/^\| +/, "", $0)
  printf "%s,misconfigured: `%s`\n", service, $0
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
        printf "%s,misconfigured CSP: `script-src 'unsafe-inline'` allows the execution of unsafe in-page scripts and event handlers\n", service
      }
      if (dir ~ /unsafe-eval/) {
        printf "%s,misconfigured CSP: `script-src 'unsafe-eval'` allows the execution of code injected into DOM APIs such as `eval()`\n", service
      }
    }

    if (dir ~ /object-src/) {
      object_src = dir
      if (dir !~ /none/) {
        printf "%s,misconfigured CSP: `%s`\n", service, dir
      }
    }
  }

  if (script_src == "missing") {
    printf "%s,misconfigured CSP: missing `script-src` directive\n", service
  }

  if (object_src == "missing") {
    printf "%s,misconfigured CSP: missing `object-src` directive allows the injection of plugins which can execute JavaScript; you should set it to `none`\n", service
  }

  next
}

tolower($0) ~ /strict-transport-security:/ {
  if (schema == "http") {
    # https://datatracker.ietf.org/doc/html/rfc6797#section-7.2
    printf "%s,misconfigured STS: an HSTS host must not include the STS header field in responses conveyed over non-secure transport (i.e. HTTP)\n", service
  }

  sub(/^\| +/, "", $0)
  hsts = $0

  match($0, /max-age=([0-9]+)/, matches)
  max_age = matches[1]

  if (max_age < 31536000) {
    printf "%s,misconfigured: `%s`\n", service, $0
  }

  next
}

tolower($0) ~ /x-content-type-options:/ {
  sub(/^\| +/, "", $0)
  x_content_type_options = $0

  if ($0 !~ /nosniff/) {
    printf "%s,misconfigured: `%s`\n", service, $0
  }

  next
}

tolower($0) ~ /referrer-policy:/ {
  sub(/^\| +/, "", $0)
  referrer_policy = $0

  if ($0 ~ /unsafe-url/) {
    printf "%s,misconfigured: `%s`\n", service, $0
  }

  next
}

ENDFILE {
  if (host) {
    if (state != "http-headers") {
      printf "error analysing file: no HTTP headers found\n"
    } else {
      if (x_frame_options == "missing") {
        printf "%s,missing `X-Frame-Options` header\n", service
      }

      if (csp == "missing") {
        printf "%s,missing `Content-Security-Policy` header\n", service
      }

      if (hsts == "missing") {
        printf "%s,missing `Strict-Transport-Security` header\n", service
      }

      if (x_content_type_options == "missing") {
        printf "%s,missing `X-Content-Type-Options` header\n", service
      }

      if (referrer_policy == "missing") {
        printf "%s,missing `Referrer-Policy` header\n", service
      }
    }
  }
}
