# recon tool suite

Based on the services identified on a network host, we often need to run specific tools to assess the security/configuration of these services.
The recon tool suite can help you automate that and analyze/summarize the results.

## motivation

Instead of manually running various tools (e.g. [testssl.sh](https://testssl.sh/), [Nikto](https://cirt.net/nikto2), [feroxbuster](https://github.com/epi052/feroxbuster), etc.) and having to remember all commands and the necessary options, we can configure them once (see [`config/scans.toml`](config/scans.toml)) and have the scanner (i.e. `scan.py`) run the required/appropriate tools based on what the Nmap service scan (e.g. `services.xml`) has found.
In addition to that, the suite also provides a tool to analyze and summarize the results of some scans (e.g. HTTP response headers, DNS/IKE/SSH/TLS configuration, etc.).
This allows for an automated and consistent assessment of specific services (i.e. no longer are testers forced to analyze configurations by hand).

## installation

Install the required tools:

```shell
git clone https://github.com/cddmp/enum4linux-ng.git && (cd enum4linux-ng; sudo python3 setup.py install)
sudo apt install curl dnsutils feroxbuster ike-scan nikto nmap onesixtyone seclists smbclient snmp sslyze testssl.sh whatweb python3-toml python3-rich python3-defusedxml python3-dnspython
```

Install the tool suite:

```shell
cd /path/to/tools
git clone https://github.com/4elta/recon.git
cd recon
```

Make sure that the scripts have the *executable* flag set:

```shell
chmod +x analyze.py
chmod +x scan.py
chmod +x scanners/*
```

Add (symbolic links to) the scripts to `/usr/local/bin`:

```shell
sudo ln --symbolic $(realpath analyze.py) /usr/local/bin/analyze
sudo ln --symbolic $(realpath scan.py) /usr/local/bin/scan
```

## usage

### scanner

Schedule and execute various tools based on the findings of the Nmap service scan:

```text
$ scan -h
usage: scan [-h] [-i INPUT] [-o OUTPUT] [-c CONFIG] [-t CONCURRENT_TARGETS] [-s CONCURRENT_SCANS] [-m MAX_TIME] [-v] [-n] [-y] [-d DELIMITER] [--ignore_uid]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        the result file of the Nmap service scan (default: 'services.xml')
  -o OUTPUT, --output OUTPUT
                        where the results are stored (default: './recon')
  -c CONFIG, --config CONFIG
                        path to the scan configuration file (default: '/path/to/recon/config/scans.toml')
  -t CONCURRENT_TARGETS, --concurrent_targets CONCURRENT_TARGETS
                        how many targets should be scanned concurrently (default: 3)
  -s CONCURRENT_SCANS, --concurrent_scans CONCURRENT_SCANS
                        how many scans should be running concurrently on a single target (default: 2)
  -m MAX_TIME, --max_time MAX_TIME
                        maximum time in seconds each scan is allowed to take (default: 3600)
  -v, --verbose         show additional info including all output of all scans
  -n, --dry_run         do not run any command; just create/update the 'commands.csv' file
  -y, --overwrite_results
                        overwrite existing result files
  -d DELIMITER, --delimiter DELIMITER
                        character used to delimit columns in the 'commands.csv' and 'services.csv' files (default: ',')
  --ignore_uid          ignore the warning about incorrect UID.
```

### analysis

Analyze and summarize the results of specific tools previously run by the scanner:

```text
$ analyze -h
usage: analyze [-h] [-t TOOL] [-r RECOMMENDATIONS] [-i INPUT] [--json JSON] [--csv CSV] {dns,http,isakmp,ntp,ssh,tls}

positional arguments:
  {dns,http,isakmp,ntp,ssh,tls}
                        specify the service that should be analyzed

optional arguments:
  -h, --help            show this help message and exit
  -t TOOL, --tool TOOL  specify the tool whose results are to be parsed
  -r RECOMMENDATIONS, --recommendations RECOMMENDATIONS
                        path to the recommendations document (default: '/path/to/recon/config/recommendations/<service>/default.toml')
  -i INPUT, --input INPUT
                        path to the root directory that holds the results to be analysed (default: './recon')
  --json JSON           in addition to the analysis printed in Markdown to STDOUT, also save the analysis as a JSON document
  --csv CSV             in addition to the analysis printed in Markdown to STDOUT, also save the analysis as a CSV document
```

The following analyzers (and parsers) are currently implemented:

* DNS configuration (`name_server`, `nmap`)
* HTTP response headers (`nmap`)
* ISAKMP/IKE configuration (`ike`)
* NTP configuration (`nmap`)
* SSH configuration (`nmap`)
* TLS configuration (`testssl`, `sslscan` or `sslyze`)

If you need the analysis in a markup format other than Markdown, just [pipe](https://en.wikipedia.org/wiki/Pipeline_(Unix)) the output of the analyzer to [`pandoc`](https://pandoc.org/) and you are good to go.
Below is an example of a conversion to `docx`:

```text
$ analyze [...] | pandoc --from=markdown --to=docx --output="/path/to/analysis.docx"
```

## contribution

If we have piqued your interest in this project (e.g. to contribute some ideas or a new tool to be included, or even an analyzer), the [architecture documentation](documentation/architecture.md) might be a good place to start to learn how the different components of this tool suite work together.
