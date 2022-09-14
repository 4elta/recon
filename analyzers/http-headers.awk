#!/usr/bin/awk -f
# parse and analyze web server response headers (i.e. curl index)
# https://csp-evaluator.withgoogle.com/

# invoke this program like this:
# /path/to/this/file /path/to/recon/*/services/*-index.log

BEGINFILE {
  host = ""
  status_line = ""
  
  x_frame_options = "missing"
  csp = "missing"
  hsts = "missing"
  x_content_type_options = "missing"
  referrer_policy = "missing"
}

/^# http/ {
  sub("\r", "", $0)

  split($0, url, "://")
  schema = url[1]
  sub(/[# ]+/, "", schema)

  split(url[2], authority, ":")
  host = authority[1]
  port = authority[2]
  sub("/", "", port)

  printf "\n#### %s://%s:%s/\n\n", schema, host, port

  if (schema == "http") {
    hsts = "none"
  }

  next
}

# status line
# https://www.rfc-editor.org/rfc/rfc2616#section-6.1
/^HTTP\/[0-9]+(\.[0-9]+)? [0-9]{3} (\w+\s?)+$/ {
  sub("\r", "", $0)
  status_line = $0

  next
}

tolower($0) ~ /^x-frame-options:/ {
  sub("\r", "", $0)
  x_frame_options = $0

  if ($0 !~ /DENY/ && $0 !~ /SAMEORIGIN/) {
    printf "* misconfigured: `%s`\n", $0
  }
  
  next
}

tolower($0) ~ /^x-xss-protection:/ && ! /0/ {
  sub("\r", "", $0)
  printf "* misconfigured: `%s`\n", $0
  next
}

tolower($0) ~ /^content-security-policy:/ {
  sub("\r", "", $0)
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
      }
      if (dir ~ /unsafe-eval/) {
        printf "* misconfigured CSP: `script-src 'unsafe-eval'` allows the execution of code injected into DOM APIs such as `eval()`\n"
      }
    }

    if (dir ~ /object-src/) {
      object_src = dir
      if (dir !~ /none/) {
        printf "* misconfigured CSP: `%s`\n", dir
      }
    }
  }

  if (script_src == "missing") {
    printf "* misconfigured CSP: missing `script-src` directive\n"
  }

  if (object_src == "missing") {
    printf "* misconfigured CSP: missing `object-src` directive allows the injection of plugins which can execute JavaScript; you should set it to `none`\n"
  }

  next
}

tolower($0) ~ /^strict-transport-security:/ {
  if (schema == "http") {
    # https://datatracker.ietf.org/doc/html/rfc6797#section-7.2
    printf "* misconfigured STS: an HSTS host must not include the STS header field in responses conveyed over non-secure transport (i.e. HTTP)\n"
  }

  sub("\r", "", $0)
  hsts = $0

  if ($0 !~ /max-age=63072000/) {
    printf "* misconfigured: `%s`\n", $0
  }

  next
}

tolower($0) ~ /^x-content-type-options:/ {
  sub("\r", "", $0)
  x_content_type_options = $0

  if ($0 !~ /nosniff/) {
    printf "* misconfigured: `%s`\n", $0
  }

  next
}

tolower($0) ~ /^referrer-policy:/ {
  sub("\r", "", $0)
  referrer_policy = $0

  if ($0 ~ /unsafe-url/) {
    printf "* misconfigured: `%s`\n", $0
  }

  next
}

# ignore HTML body
/</ {
  nextfile
}

ENDFILE {
  if (host) {
    if (! status_line) {
      printf "error analysing file: HTTP status line missing\n"
    } else {
      if (x_frame_options == "missing") {
        printf "* missing `X-Frame-Options` header\n"
      }

      if (csp == "missing") {
        printf "* missing `Content-Security-Policy` header\n"
      }

      if (hsts == "missing") {
        printf "* missing `Strict-Transport-Security` header\n"
      }

      if (x_content_type_options == "missing") {
        printf "* missing `X-Content-Type-Options` header\n"
      }

      if (referrer_policy == "missing") {
        printf "* missing `Referrer-Policy` header\n"
      }
    }
  }
}
