When started perf_root crawls the DNS root zone for a number of
TLDs. It then issues timed queries to each root server identity over UDP and TCP, IPv4
and IPv6. Traceroutes are also performed to each root server identity
over IPv4 and IPv6.

Results of these tests are then output in JSON.

## Usage
``
perf_root.py [-h] [-d DELAY] [-n NUM_TLDS] [-o OUT_FILE]
                    [-q QUERY_TIMEOUT] [-t NUM_TESTS] [-v]
                    [--threads {1,2,3,4,5,6}] [--no-tcp] [--no-udp]
                    [--no-ipv4] [--no-ipv6] [--no-traceroute]
``

``-h, --help``
show this help message and exit

``-d DELAY, --delay DELAY``
Delay between tests in seconds (default: 0.05)

``-n NUM_TLDS, --num-tlds NUM_TLDS``
Number of TLDs to test (default: 10)

``-o OUT_FILE, --out-file OUT_FILE``
Filename for output (default: )

``-q QUERY_TIMEOUT, --query-timeout QUERY_TIMEOUT``
DNS query timeout in seconds (default: 10)

``-t NUM_TESTS, --num-tests NUM_TESTS``
Number of tests per-TLD (default: 2)

``-v, --verbose``
Verbose output, repeat for increased verbosity

``--threads {1,2,3,4,5,6}``
Number of threads to run concurrently (default: 6)

``--no-tcp``
Turn off TCP testing

``--no-udp``
Turn off UDP testing

``--no-ipv4``
Turn off IPv4 testing

``--no-ipv6``
Turn off IPv6 testing

``--no-traceroute``
Turn off traceroute for both IPv4 and IPv6

If --out-file is not specified stdout is used. UDP port 53 is used for
traceroute probes.

# Installation
perf_root.py requires Python3 and the dnspython library.
