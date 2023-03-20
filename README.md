# recon tool suite

Based on the services identified on a network host, we often need to run specific tools to assess the security/configuration of these services.
The recon tool suite can help you automate that and analyze/summarize the results.

## motivation

Instead of manually running various tools (e.g. [sslyze](https://github.com/nabla-c0d3/sslyze), [Nikto](https://cirt.net/nikto2), [feroxbuster](https://github.com/epi052/feroxbuster), etc.) and having to remember all commands and the necessary options, we can configure the recon tool (see [`config/recon.toml`](config/recon.toml)) and have it run the required/appropriate tools based on what the Nmap service scan (e.g. `services.xml`) has found.
In addition to that, the suite also provides tools to analyze and summarize the results of some scans (e.g. HTTP security headers, TLS/SSH/IKE configuration, etc.).
This allows for an automated and consistent assessment of specific services (i.e. no longer are testers forced to analyze TLS/SSH configurations by hand).

## installation

Install the required tools:

```sh
git clone https://github.com/cddmp/enum4linux-ng.git && (cd enum4linux-ng; sudo python3 setup.py install)
sudo apt install curl dnsutils feroxbuster ike-scan nikto nmap onesixtyone seclists smbclient snmp sslyze testssl.sh whatweb python3-toml python3-rich python3 defusedxml
```

Install the tool suite:

```sh
cd /path/to/tools
git clone https://github.com/4elta/recon.git
cd recon
```

Be sure to have the scripts of the suite in your `PATH` variable; at least the `icke.sh` should be, as it is only referenced by name (in `config/recon.toml`).
Also, make sure that the scripts have the *executable* flag set.

```sh
chmod +x analyze.py
chmod +x icke.sh
chmod +x recon.py
ln -s $(realpath analyze.py) /usr/local/bin/analyze
ln -s $(realpath icke.sh) /usr/local/bin/icke
ln -s $(realpath recon.py) /usr/local/bin/recon
```

## usage

### scanner

schedule and execute various tools based on the findings of the Nmap service scan:

```text
$ recon -h
usage: recon [-h] [-i INPUT] [-o OUTPUT] [-c CONFIG] [-t CONCURRENT_TARGETS] [-s CONCURRENT_SCANS] [-v] [-n] [-y]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        the result file of the Nmap service scan (default: 'services.xml')
  -o OUTPUT, --output OUTPUT
                        where the results are stored (default: './recon')
  -c CONFIG, --config CONFIG
                        path to the scan configuration file (default: '/path/to/recon-suite/config/recon.toml')
  -t CONCURRENT_TARGETS, --concurrent_targets CONCURRENT_TARGETS
                        how many targets should be scanned concurrently (default: 3)
  -s CONCURRENT_SCANS, --concurrent_scans CONCURRENT_SCANS
                        how many scans should be running concurrently on a single target (default: 2)
  -v, --verbose         show additional info including all output of all scans
  -n, --dry_run         do not run any command; just create/update the 'commands.csv' file
  -y, --overwrite_results
                        overwrite existing result files
  -d DELIMITER, --delimiter DELIMITER
                        character used to delimit columns in the 'commands.csv' file (default: ',')
```

### analysis

analyze and summarize the results of specific tools previously run by the scanner:

```text
$ analyze -h
usage: analyze [-h] [-i INPUT] [--json JSON] [--csv CSV] {http,isakmp,ssh,tls} tool recommendations

positional arguments:
  {http,isakmp,ssh,tls}
                        specify the service/protocol whose results are to be analyzed
  tool                  specify the tool whose results are to be analyzed
  recommendations       path to the recommendations document (e.g.: '/path/to/recon/config/recommendations/tls/mozilla-intermediate.toml')

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        path to the root directory that holds the results to be analysed (default: './recon')
  --json JSON           in addition to the analysis printed in Markdown to STDOUT, also save the analysis as a JSON document
  --csv CSV             in addition to the analysis printed in Markdown to STDOUT, also save the analysis as a CSV document
```

currently implemented analyzers:

* TLS configuration (via the results from `testssl`, `sslscan` or `sslyze`)
* SSH configuration (via the results from `nmap`)
* HTTP configuration (via the results from `nmap`)
* ISAKMP/IKE configuration (via the results from `icke`)

If you need the analysis in a markup format other than Markdown, just [pipe](https://en.wikipedia.org/wiki/Pipeline_(Unix)) the output of the analyzer to [`pandoc`](https://pandoc.org/) and you are good to go.
Below is an example of a conversion to `docx`:

```text
$ analyze [...] | pandoc --from=markdown --to=docx --output="/path/to/analysis.docx"
```

## contribution

In case we have excited your interest in this project (e.g. to contribute some ideas or a new tool to include, or even an analyzer), the [architecture documentation](documentation/architecture.md) might be a great start to learn how the different components of this tool suite are working together.
