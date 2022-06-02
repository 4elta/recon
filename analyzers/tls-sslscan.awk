#!/usr/bin/awk -f
# parse and analyze sslscan result files

# invoke this program like this:
# /path/to/this/file /path/to/recon/*/services/*-sslscan.log

function iso_date(epoch) {
  # convert the UNIX epoch into ISO date/time format
  cmd = "date --date='@" epoch "' --iso-8601=seconds"
  cmd | getline date_time
  close(cmd)

  return date_time
}

BEGIN {
  # get the current date/time in seconds since the UNIX epoch
  cmd = "date \"+%s\""
  cmd | getline current_datetime
  #print current_datetime "\n"

  # look-ahead time for expiring certificates
  look_ahead_days = 30
  look_ahead_time = look_ahead_days * 24 * 60 * 60
}

/^Testing SSL server .+ on port [0-9]+ using SNI name .+$/ {
  #Testing SSL server 11.22.33.44 on port 55 using SNI name www.example.com
  #1       2   3      4           5  6    7  8     9   10   11
  printf "\n**%s:%d**\n\n", $4, $7
}

/^SSLv(2|3) +enabled$/ || /^TLSv1.(0|1) +enabled$/ || /^TLSv1.3 +disabled$/ {
  printf "* %s %s\n", $1, $2
}

/^Server does not support TLS Fallback SCSV$/ {
  print "* TLS Fallback SCSV not supported: vulnerable to POODLE"
}

/^Insecure session renegotiation supported$/ {
  print "* insecure session renegotiation supported"
}

/^Compression enabled\(CRIME\)$/ {
  print "* TLS compression enabled: vulnerable to CRIME"
}

/vulnerable to heartbleed$/ && ! /not/ {
  printf "* %s vulnerable to Heartbleed\n", $1
}

/^(Preferred|Accepted)/ && ( /-MD5/ || /-SHA / || /-3?DES-/ || /-RC(2|4)-/ || /-IDEA-/ || /ADH-/ || /GOST/ || /NULL/ || /PSK/ || /ANON/ || /DHE (768|1024) bits/ || /-CBC-/ || !/(EC)?DHE/ ) {
  # Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
  # 1         2        3   4     5                             6...

  printf "* accepted %s", $5

  if (NF > 5) {
    printf " ("
    for (i = 6; i <= NF - 1; i++) {
      printf "%s ", $i
    }
    printf "\b)"
  }

  printf " (%s)\n", $2
}

/^Not valid before: / || /^Not valid after: / {
  # Not valid before: Jan 25 00:00:00 2018 GMT
  # 1   2     3       4   5  6        7    8

  #print

  # convert the date/time string into the number of seconds since the UNIX epoch
  cmd = "date --date='" $4 " " $5 " " $6 " " $7 " " $8 "' \"+%s\""
  cmd | getline datetime
  #print datetime
  close(cmd)

  if ($3 == "before:" && current_datetime <= datetime) {
    printf "* certificate will only be valid after %s\n", iso_date(datetime)
  }

  if ($3 == "after:") {
    if (current_datetime + look_ahead >= datetime) {
      printf "* certificate expired since %s\n", iso_date(datetime)
    } else if (current_datetime + look_ahead_time >= datetime) {
      printf "* certificate expires in %s days or less (%s)\n", look_ahead_days, iso_date(datetime)
    }
  }
}
