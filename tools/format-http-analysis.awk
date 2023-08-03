# this script formats the HTTP analysis in table form.
# it requires the CSV from the HTTP analysis.
# it will print a CSV (the columns are separated by a tabulator).

# run this script like this:
# awk -f /path/to/this/script.awk \
#     /path/to/services.csv

function reset_headers() {
  headers["strict-transport-security"] = "OK"
  headers["content-security-policy"] = "OK"
  headers["x-content-type-options"] = "OK"
  headers["x-frame-options"] = "OK"
  headers["x-xss-protection"] = "OK"
  headers["referrer-policy"] = "OK"
}

function print_table_header() {
  printf "asset\t"

  for (name in headers) {
    printf "%s\t", name
  }
}

function print_table_row(asset) {
  printf "\n%s\t", asset

  for (name in headers) {
    printf "%s\t", headers[name]
  }
}

BEGIN {
  FS = ","
  asset = ""

  reset_headers()
  print_table_header()
}

# ignore header
/asset,issues/ {
  next
}

$1 != asset {
  if (asset) {
    print_table_row(asset)
  }

  asset = $1

  reset_headers()
}

{
  for (name in headers) {
    if ($2 ~ name) {
      headers[name] = "not OK"
      next
    }
  }
}

END {
  if (asset) {
    print_table_row(asset)
  }
  printf "\n"
}
