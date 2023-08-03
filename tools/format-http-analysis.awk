# this script formats the HTTP analysis in table form.
# it requires the HTTP analysis as CSVs.
# it will print CSVs (the columns are separated by a tabulator).

# run this script like this:
# awk -f /path/to/this/script.awk \
#     /path/to/services.csv

function reset_row(asset) {
  row["0:asset"] = asset
  row["1:strict-transport-security"] = "OK"
  row["2:content-security-policy"] = "OK"
  row["3:x-content-type-options"] = "OK"
  row["4:x-frame-options"] = "OK"
  row["5:x-xss-protection"] = "OK"
  row["6:referrer-policy"] = "OK"
}

function print_header() {
  for (name in row) {
    split(name, tokens, ":")
    printf "%s\t", tokens[2]
  }
  printf "\n"
}

function print_row() {
  for (name in row) {
    printf "%s\t", row[name]
  }
  printf "\n"
}

BEGIN {
  PROCINFO["sorted_in"] = "@ind_str_asc"
  FS = ","
  reset_row("")
  print_header()
}

# ignore header
/asset,issues/ {
  next
}

$1 != row["0:asset"] {
  if (row["0:asset"]) {
    print_row()
  }
  reset_row($1)
}

{
  for (name in row) {
    split(name, tokens, ":")
    if ($2 ~ tokens[2]) {
      row[name] = "not OK"
      next
    }
  }
}

END {
  if (row["0:asset"]) {
    print_row()
  }
}
