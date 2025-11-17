EvilTelnet

A fast Telnet anonymous and credential checker built with pexpect.
Designed for pentesting workflows where you need to quickly identify:

Anonymous / no-login Telnet access
Valid username/password combinations
Banner/session output on successful logins
Includes optional logging, verbose/debug modes, and a --test-all mode to try all credentials per host even after a success.

Features :

🔍 Detect anonymous / no-auth Telnet access

🔐 Test single or multiple credentials (user:pass file)

📄 Log all events, successes only, or full session output

🚀 Fast, non-interactive scanning using pexpect

🔁 --test-all to enumerate all valid creds per host

🎛 Optional verbose and session output display


Usage :

./EvilTelnet.py [options] <hosts_file>

Common options:
-t <sec>         Set timeout (default: 10)
-v               Verbose output
-c FILE          Cred file (username:password per line)
-u USER -p PASS  Single credential
--test-all       Try all credentials even after a success
--show-session   Print captured session output
--log-all FILE
--log-success FILE
--log-success-list FILE

Example:

./EvilTelnet.py hosts.txt -c creds.txt --test-all --log-success success.log


Requirements :

pip install pexpect colorama


Notes :

Uses a lightweight heuristic to detect prompts/banners.
Built for offensive security / pentest environments.
For legal and authorized use only.

