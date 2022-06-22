# FortiFuck-Checker

Tool written in Bash script to check CVE-2018-13379.
## Usage:
```
-h      Get this help message
-t      Insert a valid IP Address to check. IP:port
-l      Provide a path to a file containing a list of IPs, one per line IP:port
-c      Provide a country name if you're interested in a specific country's IPs
-o      Output filename
```
## Examples:
```
checker.sh -t 1.1.1.1:4444
checker.sh -t 1.1.1.1:4444 -o /path/to/outfile
checker.sh -l /path/to/file
checker.sh -l /path/to/file -o /path/to/outfile
checker.sh -l /path/to/file -c Germany
checker.sh -l /path/to/file -c Germany -o /path/to/outfile

```
