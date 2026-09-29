import argparse
from ssh_honeypot import *
from web_honeypot import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-pw', '--password', type=str)

    parser.add_argument('-s', '--ssh', action="store_true")
    parser.add_argument('-w', '--http', action="store_true")

    args = parser.parse_args()

    try:
        if args.ssh:
            print("[-] Running SSH Honeypot...")
            honeypot(args.address, args.port, args.username, args.password)
        elif args.http:
            print("[-] Running HTTP WordPress Honeypot...")

            if not args.username:
                args.username = "admin"
            if not args.password:
                args.password = "password"

            print(f'Address: {args.address} Port: {args.port} '
                  f'Username: {args.username} Password: {args.password}')
            run_web_honeypot(host=args.address, port=args.port,
                              input_username=args.username,
                              input_password=args.password)
        else:
            print("[!] Choose a honeypot type (SSH --ssh) or (HTTP --http).")
    except KeyboardInterrupt:
        print("\n Exiting HONEYPY...")