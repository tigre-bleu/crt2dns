# crt2dns

This simple tool takes a list of hosts and ports, then connects to them and tries to harvest DNS names in `commonName` or `subjectAltName` attributes of the certificates.

## Usage

```
usage: crt2dns.py [-h] [-f FORMAT] [-o OUTPUT] [--timeout TIMEOUT] [-v] [-q] [-t THREADS] files [files ...]

Find DNS subdomains from TLS certificates

positional arguments:
  files                 Files to push

options:
  -h, --help            show this help message and exit
  -f, --format FORMAT   Input file format xml: Nmap XML hostport: one line per host:port)
  -o, --output OUTPUT   File output
  --timeout TIMEOUT     Timeout when establishing connection (in seconds, default=5)
  -v, --verbose         Show verbose output
  -q, --quiet           Only show results
  -t, --threads THREADS
                        Number of threads to run (default=5)
```