# WebEnum
A fast DNS and HTTP path scanner

```
usage: WebEnum [-h] [-s] [-d DEPTH] [-t THREADS] [-p PROXY] [-j] wordlist path

Bruteforce HTTP URIs and subdomains

positional arguments:
  wordlist
  path                  Either URI or FQDN

options:
  -h, --help            show this help message and exit
  -s, --trailing-slash  Append trailing slash to tested URLs
  -d DEPTH, --depth DEPTH
  -t THREADS, --threads THREADS
                        How many threads to run. More - faster scanning.
  -p PROXY, --proxy PROXY
  -j, --json            Output scan results as JSON
```
