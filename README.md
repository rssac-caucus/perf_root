rootperf.py performs DNS queries and traceroutes to the DNS root servers. Results of these tests are then output in JSON.

By default rootperf.py performs the tests specified in
RSSAC057.

## Usage
``
rootperf.py [-h] [-d DELAY] [-n NUM_TESTS] [-o OUT_FILE]
                    [-q QUERY_TIMEOUT] [-t TLDS] [-v]
                    [--threads {1,2,3,4,5,6}] [--no-tcp] [--no-udp]
                    [--no-ipv4] [--no-ipv6] [--no-traceroute]
``

``-h, --help``
show this help message and exit

``-d DELAY, --delay DELAY``
Delay between tests in seconds (default: 0.05)

``-n NUM_TESTS, --num-tests NUM_TESTS``
Number of test cycles per-TLD (default: 10)

``-o OUT_FILE, --out-file OUT_FILE``
Filename for output (default: )

By default rootperf.py outputs to the user's tty.

``-q QUERY_TIMEOUT, --query-timeout QUERY_TIMEOUT``
DNS query timeout in seconds (default: 1)

`` -t TLDS, --tlds TLDS ``
Comma separated list of TLDs to query, or number between 1 and 100 for
random TLDs (default: com)

If passed a comma separated list of TLDs rootperf.py will use them. If
passed a number between 1-100 rootperf.py will choose a random place
in the root zone then crawl it to determine a random set of TLDs to use.

``-v, --verbose``
Verbose output, repeat for increased verbosity (max: 3)

``--threads {1,2,3,4,5,6}``
Number of threads to run concurrently (default: 6)

By default each test is run asynchronously using a pool of
threads. Decreasing the number of threads could theorhetically provide
more accurate results at the expense of test duration.

``--no-tcp``
Disable TCP testing

``--no-udp``
Disable UDP testing

``--no-ipv4``
Disable IPv4 testing

``--no-ipv6``
Disable IPv6 testing

``--no-traceroute``
Disable traceroute for both IPv4 and IPv6

UDP port 53 is used for traceroute probes.

# Installation
rootperf.py requires Python3 and dnspython 2.2.0 or higher.
