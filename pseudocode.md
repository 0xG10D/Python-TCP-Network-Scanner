# Pseudocode for `scanner.py`

```text
START PROGRAM

DEFINE defaults for workers, timeout, and CSV output path
DEFINE maximum scan size to reduce accidental oversized scans

PARSE command-line arguments:
    required start IPv4 address
    required end IPv4 address
    required TCP port
    optional workers, timeout, and output path

VALIDATE input:
    start and end must be IPv4 addresses
    start must be less than or equal to end
    TCP port must be between 1 and 65535
    workers and timeout must be greater than zero
    workers must not exceed the worker safety limit
    timeout must be finite and must not exceed its safety limit
    output filename must end in .csv
    range must stay in private, loopback, or IPv4 link-local space
    range must not exceed the safety limit

GENERATE every IPv4 address from start through end, including both endpoints
START elapsed-time timer
CREATE a thread pool with the requested worker count

FOR each IPv4 address:
    SUBMIT scan tasks only until the worker-sized in-flight window is full

FOR each completed scan task:
    CREATE a new immutable result
    IF TCP connection succeeds:
        SET state to "open"
        TRY reverse DNS lookup
        STOP waiting after the reverse-DNS time limit
        USE "Unknown" if reverse DNS fails
    ELSE IF connection is explicitly refused:
        SET state to "closed"
    ELSE:
        SET state to "error"
        RECORD a readable error message
    RECORD an ISO 8601 UTC timestamp
    COLLECT the result
    SUBMIT the next address so the in-flight window stays bounded

IF Ctrl+C occurs:
    CANCEL pending tasks
    SHUT DOWN the thread pool
    PRINT a clean interruption message
    EXIT with interruption status

SORT all collected results by the numeric value of each IPv4 address
STOP elapsed-time timer
FILTER results so only state "open" is exported by default
NEUTRALIZE hostname text that spreadsheet software could treat as a formula
WRITE CSV header and selected rows to a temporary file
ATOMICALLY replace the requested CSV only after writing succeeds
IF no ports are open:
    WRITE a header-only CSV file

PRINT summary:
    addresses scanned
    open ports found
    errors
    elapsed time
    selected output file path

REMIND the user that a closed or unreachable port does not prove the host is offline
END PROGRAM
```
