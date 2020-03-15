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
Delay between tests in seconds (default: 0.5)

``-n NUM_TLDS, --num-tlds NUM_TLDS``
Number of TLDs to test (default: 10)

``-o OUT_FILE, --out-file OUT_FILE``
Filename for output (default: )

``-q QUERY_TIMEOUT, --query-timeout QUERY_TIMEOUT``
DNS query timeout in seconds (default: 30)

``-r ROOT_HINTS, --root-hints ROOT_HINTS``
Root hints file (default: named.cache)

``-t NUM_TESTS, --num-tests NUM_TESTS``
Number of tests per-TLS (default: 2)

``-v, --verbose``
Verbose output, repeat for increased verbosity
                        (default: 0)

If no --out-file is specified stdout is used.
