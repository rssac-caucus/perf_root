When launched perf_root crawls the DNS root zone for a number of
TLDs. It then issues timed queries to each TLD over UDP. Results of these tests
are then output in JSON.

## Usage
``
perf_root.py [-h] [-d DELAY] [-n NUM_TLDS] [-o OUT_FILE]
                    [-q QUERY_TIMEOUT] [-r ROOT_HINTS] [-t NUM_TESTS] [-v]
``

``-h, --help``
show this help message and exit

``-d DELAY, --delay DELAY``
Delay between tests in seconds (default: 0.2)

``-n NUM_TLDS, --num-tlds NUM_TLDS``
Number of TLDs to test (default: 10)

``-o OUT_FILE, --out-file OUT_FILE``
Filename for output (default: )

``-q QUERY_TIMEOUT, --query-timeout QUERY_TIMEOUT``
DNS query timeout in seconds (default: 10)

``-r ROOT_HINTS, --root-hints ROOT_HINTS``
Root hints file (default: named.cache)

``-t NUM_TESTS, --num-tests NUM_TESTS``
Number of tests per-TLD (default: 2)

``-v, --verbose``
Verbose output, repeat for increased verbosity

``--no-tcp``
Turn off TCP testing (default: False)

``--no-udp``
Turn off UDP testing (default: False)

``--no-ipv4``
Turn off IPv4 testing (default: False)

``--no-ipv6``
Turn off IPv6 testing (default: False)


If no --out-file is specified stdout is used.
