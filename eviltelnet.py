#!/usr/bin/env python3
r"""
EvilTelnet — Telnet anonymous / credential checker (pexpect-based)
Added --test-all (-C) to try all creds per host even after a success.
"""

import sys
import argparse
import time
from datetime import datetime
from pathlib import Path
import io
import re

try:
    import pexpect
except Exception:
    print("This script requires pexpect. Install with: python3 -m pip install --user pexpect")
    raise

try:
    from colorama import Fore, Style, init as colorama_init
except Exception:
    print("This script requires colorama. Install with: python3 -m pip install --user colorama")
    raise

colorama_init(autoreset=True)

BANNER = r"""
 __   _____       _ _ _____    _            _     __ 
| _| | ____|_   _(_) |_   _|__| |_ __   ___| |_  |_ |
| |  |  _| \ \ / / | | | |/ _ \ | '_ \ / _ \ __|  | |
| |  | |___ \ V /| | | | |  __/ | | | |  __/ |_   | |
| |  |_____| \_/ |_|_| |_|\___|_|_| |_|\___|\__|  | |
|__|                                             |__|
"""

PROMPT_RE = r'[#>$%] ?$'  # heuristic for shell prompt

def timestamp():
    return datetime.now().isoformat(sep=' ', timespec='seconds')

def write_line(fh, line):
    try:
        fh.write(line + "\n")
        fh.flush()
    except Exception:
        pass

def print_banner():
    print(Fore.MAGENTA + Style.BRIGHT + BANNER + Style.RESET_ALL)

def load_hosts_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.YELLOW + f"Hosts file not found: {path}" + Style.RESET_ALL)
        sys.exit(1)

def load_credentials_file(path):
    creds = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    u, p = line.split(':', 1)
                    creds.append((u.strip(), p.strip()))
    except FileNotFoundError:
        print(Fore.YELLOW + f"Credentials file not found: {path}" + Style.RESET_ALL)
        sys.exit(1)
    return creds

def capture_output(child, timeout):
    """Read whatever output is available from pexpect child for up to `timeout` seconds."""
    end = time.time() + timeout
    out_chunks = []
    try:
        while time.time() < end:
            try:
                chunk = child.read_nonblocking(size=4096, timeout=0.2)
                if not chunk:
                    break
                out_chunks.append(chunk)
            except pexpect.exceptions.TIMEOUT:
                continue
            except pexpect.exceptions.EOF:
                break
    except Exception:
        pass
    return "".join(out_chunks)

def try_anonymous(child, timeout, verbose):
    """
    Consider a successful anonymous/no-login if:
      - the telnet child remains alive after a short window, OR
      - any non-empty output (banner/menu) is observed.
    Return (success_bool, captured_output_str).
    """
    try:
        out = capture_output(child, timeout)
        if getattr(child, 'isalive', lambda: False)() and (out and out.strip() or True):
            return True, out
        return False, out
    except Exception:
        return False, ""

def try_credentials(child, username, password, timeout, verbose):
    """Send username/password and check for prompt. Return (success, output)."""
    try:
        try:
            child.expect([r'login[: ]', r'username[: ]', r'Login[: ]', r'Username[: ]'], timeout=2)
            child.sendline(username)
        except pexpect.exceptions.TIMEOUT:
            child.sendline(username)

        try:
            child.expect([r'Password[: ]', r'password[: ]'], timeout=2)
            child.sendline(password)
        except pexpect.exceptions.TIMEOUT:
            pass

        idx = child.expect([PROMPT_RE, r'Login incorrect', r'Authentication failed', pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
        out = capture_output(child, 0.8)
        if idx == 0:
            return True, out
        return False, out
    except Exception:
        return False, ""

def check_telnet_host(host, timeout, creds, single_cred, verbose,
                      fh_all, fh_success, fh_success_list, show_session=False, test_all=False):
    """
    Check host:
      - capture telnet output to avoid printing to terminal
      - detect anonymous/no-login by connection + banner
      - try credentials (single then file)
      - test_all: if True, don't stop after first success; record all successes
    """
    print(Fore.BLUE + f"[ * ] - Connecting to {host}..." + Style.RESET_ALL)
    if fh_all:
        write_line(fh_all, f"{timestamp()} | CONNECTING | {host}")

    cmd = f"telnet {host}"
    child = None
    try:
        child = pexpect.spawn(cmd, timeout=timeout, encoding='utf-8', codec_errors='ignore')
        child.logfile = io.StringIO()
        child.logfile_read = io.StringIO()
        child.delaybeforesend = 0

        try:
            _ = child.read_nonblocking(size=2048, timeout=0.6)
        except Exception:
            pass

        # 1) Anonymous / connection detection
        anon_success = False
        anon_out = ""
        try:
            anon_success, anon_out = try_anonymous(child, timeout=1.2, verbose=verbose)
        except Exception:
            anon_success, anon_out = False, ""

        if anon_success:
            print(Fore.GREEN + f"[ * ] - Telnet anonymous / no-login allowed on {host}." + Style.RESET_ALL)
            if fh_all:
                write_line(fh_all, f"{timestamp()} | ANONYMOUS_SUCCESS | {host}")
            if fh_success:
                write_line(fh_success, f"{timestamp()} | {host} | ANONYMOUS_SUCCESS")
            if fh_success_list:
                write_line(fh_success_list, f"{timestamp()} | {host} | SESSION_OUTPUT_START")
                for ln in (anon_out or "").splitlines():
                    write_line(fh_success_list, ln)
                write_line(fh_success_list, f"{timestamp()} | {host} | SESSION_OUTPUT_END")

            if show_session and anon_out:
                print(Fore.CYAN + "--- session output start ---" + Style.RESET_ALL)
                print(anon_out)
                print(Fore.CYAN + "--- session output end ---" + Style.RESET_ALL)

            # If test_all is False -> stop here (old behavior). If True -> continue trying creds.
            try:
                child.close(force=True)
            except Exception:
                pass
            if not test_all:
                return
        else:
            try:
                child.close(force=True)
            except Exception:
                pass

        # 2) Credential attempts: single_cred first, then file creds
        attempts = []
        if single_cred:
            attempts.append(single_cred)
        attempts.extend(creds)

        success_any = False
        for (username, password) in attempts:
            try:
                child = pexpect.spawn(cmd, timeout=timeout, encoding='utf-8', codec_errors='ignore')
                child.logfile = io.StringIO()
                child.logfile_read = io.StringIO()
                child.delaybeforesend = 0
                time.sleep(0.2)
                ok, out = try_credentials(child, username, password, timeout=3, verbose=verbose)
                if ok:
                    success_any = True
                    print(Fore.GREEN + f"[ * ] - Login successful on {host} with {username}:{password}" + Style.RESET_ALL)
                    if fh_all:
                        write_line(fh_all, f"{timestamp()} | SUCCESS | {host} | {username}:{password}")
                    if fh_success:
                        write_line(fh_success, f"{timestamp()} | {host} | {username}:{password}")
                    if fh_success_list:
                        write_line(fh_success_list, f"{timestamp()} | {host} | SESSION_OUTPUT_START")
                        for ln in (out or "").splitlines():
                            write_line(fh_success_list, ln)
                        write_line(fh_success_list, f"{timestamp()} | {host} | SESSION_OUTPUT_END")

                    if show_session and out:
                        print(Fore.CYAN + "--- session output start ---" + Style.RESET_ALL)
                        print(out)
                        print(Fore.CYAN + "--- session output end ---" + Style.RESET_ALL)

                    try:
                        child.close(force=True)
                    except Exception:
                        pass

                    # if test_all is False, stop after first success (legacy behavior)
                    if not test_all:
                        break
                    # otherwise continue trying rest of creds
                else:
                    if verbose:
                        print(Fore.YELLOW + f"[ - ] - {host} : {username}:{password} -> Failed" + Style.RESET_ALL)
                    if fh_all:
                        write_line(fh_all, f"{timestamp()} | CRED_FAIL | {host} | {username}:{password}")
                    try:
                        child.close(force=True)
                    except Exception:
                        pass
            except Exception as e:
                if verbose:
                    print(Fore.YELLOW + f"[ ! ] - Error trying {username} on {host}: {e}" + Style.RESET_ALL)
                if fh_all:
                    write_line(fh_all, f"{timestamp()} | ERROR | {host} | {username}:{password} | {e}")
                try:
                    child.close(force=True)
                except Exception:
                    pass

        if not success_any:
            print(Fore.YELLOW + f"[ - ] - No valid credentials for {host}." + Style.RESET_ALL)
            if fh_all:
                write_line(fh_all, f"{timestamp()} | LOGIN_FAILED | {host}")
        else:
            # summary when one or more successes found (already printed each success). nothing else to do.
            pass

    except pexpect.exceptions.TIMEOUT:
        print(Fore.YELLOW + f"[ ! ] - Connection to {host} timed out." + Style.RESET_ALL)
        if fh_all:
            write_line(fh_all, f"{timestamp()} | TIMEOUT | {host}")
    except Exception as e:
        print(Fore.YELLOW + f"[ ! ] - Could not connect to {host}: {e}" + Style.RESET_ALL)
        if fh_all:
            write_line(fh_all, f"{timestamp()} | ERROR | {host} | {e}")
    finally:
        try:
            if child and child.isalive():
                child.close(force=True)
        except Exception:
            pass

def main():
    prog = Path(sys.argv[0]).name
    parser = argparse.ArgumentParser(add_help=False, usage=argparse.SUPPRESS)
    parser.add_argument("hosts_file", nargs="?", help="Path to hosts file (one host per line)")
    parser.add_argument("-t", dest="timeout", type=int, default=10, help="Timeout seconds (default: 10)")
    parser.add_argument("-v", action="store_true", dest="verbose", help="Verbose output")
    parser.add_argument("--show-session", action="store_true", help="Show captured session output to terminal (debugging only)")
    parser.add_argument("--test-all", "-C", action="store_true", help="Try all credentials per host even after a success")
    parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show help")
    parser.add_argument("--log-all", dest="log_all", help="Log all events to FILE")
    parser.add_argument("--log-success", dest="log_success", help="Log only successful logins to FILE")
    parser.add_argument("--log-success-list", dest="log_success_list", help="Log successful logins + session output")
    parser.add_argument("-c", "--credfile", dest="credfile", help="File containing username:password per line")
    parser.add_argument("-u", dest="username", help="Single username for credential attempt")
    parser.add_argument("-p", dest="password", help="Single password for credential attempt")
    args = parser.parse_args()

    # print banner
    print_banner()

    if args.help or not args.hosts_file:
        help_text = f"""
{Fore.GREEN}Usage:{Style.RESET_ALL}
  {prog} [options] <hosts_file>

Options:
  -t <seconds>         Timeout for connection attempts (default: 10)
  -v                   Verbose output
  -c, --credfile FILE  Use username:password combos from FILE
  -u USER -p PASS      Single username/password to try
  --test-all, -C       Try all credentials per host even after a success
  --log-all FILE       Log all events
  --log-success FILE   Log successes only
  --log-success-list FILE  Log successes with session output
  --show-session       Print captured session output to terminal (for debugging)
"""
        print(help_text)
        sys.exit(0 if args.help else 1)

    hosts = load_hosts_file(args.hosts_file)
    creds = load_credentials_file(args.credfile) if args.credfile else []
    single_cred = (args.username, args.password) if args.username and args.password else None

    # open log files
    fh_all = fh_success = fh_success_list = None
    try:
        if args.log_all:
            fh_all = open(args.log_all, "a", encoding="utf-8")
            write_line(fh_all, f"{timestamp()} | LOG START | log-all -> {args.log_all}")
        if args.log_success:
            fh_success = open(args.log_success, "a", encoding="utf-8")
            write_line(fh_success, f"{timestamp()} | LOG START | log-success -> {args.log_success}")
        if args.log_success_list:
            fh_success_list = open(args.log_success_list, "a", encoding="utf-8")
            write_line(fh_success_list, f"{timestamp()} | LOG START | log-success-list -> {args.log_success_list}")
    except Exception as e:
        print(Fore.YELLOW + f"Could not open one of the log files: {e}" + Style.RESET_ALL)
        for fh in (fh_all, fh_success, fh_success_list):
            try:
                if fh:
                    fh.close()
            except Exception:
                pass
        sys.exit(1)

    for host in hosts:
        check_telnet_host(host,
                          timeout=args.timeout,
                          creds=creds,
                          single_cred=single_cred,
                          verbose=args.verbose,
                          fh_all=fh_all,
                          fh_success=fh_success,
                          fh_success_list=fh_success_list,
                          show_session=args.show_session,
                          test_all=args.test_all)

    # close logs
    for fh in (fh_all, fh_success, fh_success_list):
        try:
            if fh:
                write_line(fh, f"{timestamp()} | LOG END")
                fh.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
