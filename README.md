# recon tool suite

Based on the services identified on a network host, we often need to run specific tools to assess the security/configuration of these services.
The recon tool suite can help you automate that and analyze/summarize the results.

## motivation

Instead of manually running various tools (e.g. [testssl.sh](https://testssl.sh/), [Nikto](https://cirt.net/nikto2), [feroxbuster](https://github.com/epi052/feroxbuster), etc.) and having to remember all commands and the necessary options, we can configure them once (see [`config/scans.toml`](config/scans.toml)) and have the scanner (i.e. `scan.py`) run the required/appropriate tools based on what the Nmap service scan (e.g. `services.xml`) has found.
In addition to that, the suite also provides a tool to analyze and summarize the results of some scans (e.g. HTTP response headers, various protocol-specific configurations, etc.).
This allows for an automated and consistent assessment of specific services (i.e. no longer are testers forced to analyze configurations by hand).

## installation

Install the dependencies:

```shell
sudo apt install \
  python3-defusedxml \
  python3-rich \
  python3-toml
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

Add (symbolic links to) the scripts to `/usr/local/bin`.
Please make sure, that the names for `analyze` and `scan` don't [conflict](https://github.com/4elta/recon/issues/31) with any binaries already installed.

```shell
sudo ln --symbolic $(realpath analyze.py) /usr/local/bin/analyze
sudo ln --symbolic $(realpath scan.py) /usr/local/bin/scan
```

### additional tools

Based on the scans you are going to run (see [`config/scans.toml`](config/scans.toml)), you might have to install additional tools:

* via `apt`:

```shell
sudo apt install \
  curl \
  python3-dnspython \
  python3-impacket \
  dnsutils \
  ike-scan \
  nmap \
  onesixtyone \
  seclists \
  smbclient \
  snmp \
  testssl.sh \
  whatweb
```

* via git:
  * [nikto](https://github.com/sullo/nikto)

* via [`pipx`](https://github.com/pypa/pipx):
  * [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)

## usage

1. run your "standard" Nmap port and service scans; just make sure to include `-sV --version-all` and `-oX services.xml`
2. run the scanner on the results of the Nmap service scan; be aware that this (like the Nmap scan itself) will send requests to the target system(s)
3. run the analyzer on the results of the scanner; no network traffic will be generated during this step

You can customize the configuration for the scanner (i.e. what tools to run, etc.) by modifying the provided one (i.e. [`config/scans.toml`](config/scans.toml)), or you can specify your own with the `--config` argument.
Similarly, you can modify the recommendations based on what the analyzers will evaluate certain services.
Make sure to have a look at the [architecture documentation](documentation/architecture.md) and/or study the provided configuration files.

### scanner

Schedule and execute various tools based on the findings of the Nmap service scan:

```text
$ scan -h
usage: scan [-h] [-i path [path ...]] [-o path] [-c path] [-t number] [-s number] [-m seconds] [-v] [-n] [-r <host>:<protocol>:<port>:<service> [<host>:<protocol>:<port>:<service> ...]] [-y] [-d character] [--ignore_uid]

optional arguments:
  -h, --help            show this help message and exit
  -i path [path ...], --input path [path ...]
                        the result file(s) of the Nmap service scan (default: 'services.xml')
  -o path, --output path
                        where the results are stored (default: './recon')
  -c path, --config path
                        path to the scan configuration file (default: '/path/to/recon/config/scans.toml')
  -t number, --concurrent_targets number
                        how many targets should be scanned concurrently (default: 3)
  -s number, --concurrent_scans number
                        how many scans should be running concurrently on a single target (default: 2)
  -m seconds, --max_time seconds
                        maximum time in seconds each scan is allowed to take (default: 3600)
  -v, --verbose         show additional info including all output of all scans
  -n, --dry_run         do not run any command; just create/update the 'commands.csv' file
  -r <host>:<protocol>:<port>:<service> [<host>:<protocol>:<port>:<service> ...], --rescan <host>:<protocol>:<port>:<service> [<host>:<protocol>:<port>:<service> ...]
                        re-scan certain hosts/protocols/ports/services and overwrite existing result files; you can use '*' if you cannot or don't want to specify a host/protocol/port/service part
  -y, --overwrite_results
                        overwrite existing result files
  -d character, --delimiter character
                        character used to delimit columns in the 'commands.csv' and 'services.csv' files (default: ',')
  --ignore_uid          ignore the warning about incorrect UID.
```

### analyzer

Analyze and summarize the results of specific tools previously run by the scanner:

```text
$ analyze -h
usage: analyze [-h] [-t TOOL] [-r RECOMMENDATIONS] [-i INPUT] [--json JSON] [--csv CSV] {?,dns,ftp,http,isakmp,ntp,rdp,ssh,tls}

positional arguments:
  {?,dns,ftp,http,isakmp,ntp,rdp,ssh,tls}
                        specify the service that should be analyzed. use '?' to list services available for analysis.

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
* DNS configuration (`nase`, `nmap`)
* FTP configuration (`nmap`)
* HTTP response headers (`nmap`)
* ISAKMP/IKE configuration (`ike`)
* NTP configuration (`ntp`, `nmap`)
* RDP configuration (`nmap`)
* SSH configuration (`nmap`)
* TLS configuration (`testssl`, `sslscan`, `sslyze`, or `nmap`)

The analyzer prints its results in Markdown, in the format expected by the [report generator](https://github.com/4elta/report-generator).
If you need the analysis in a markup format other than Markdown, just [pipe](https://en.wikipedia.org/wiki/Pipeline_(Unix)) the output of the analyzer to [`pandoc`](https://pandoc.org/) and you are good to go.
Below is an example of a conversion to `docx`:

```text
$ analyze [...] | pandoc --from=markdown --to=docx --output="/path/to/analysis.docx"
```

## contribution

If we have piqued your interest in this project (e.g. to contribute some ideas or a new tool to be included, or even an analyzer), the [architecture documentation](documentation/architecture.md) might be a good place to start to learn how the different components of this tool suite work together.
