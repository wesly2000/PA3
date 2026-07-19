"""
This file is used to test batch_capture. Also, it could be used as a simple script to for capture.
"""

from pa3.tools.capture import batch_capture, read_host_list, decide_output_file_idx
import argparse
import os
from pathlib import Path

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument('-l', '--list', type=str, help="The hostname list file to read")
    parser.add_argument('-d', '--dir', type=str, help="The base dir to which the capture will output")
    parser.add_argument('-i', '--iface', type=str, help="The interface to perform capturing")
    parser.add_argument('-r', '--repeat', type=int, default=20, help="How many times the request will repeat")
    parser.add_argument('-t', '--timeout', type=int, default=200, help="The living time for a browsing session")
    parser.add_argument('-p', '--proxy', type=str, default=None, help="Proxy protocol, None if no proxy enabled")
    parser.add_argument('--dry-run', action='store_true', help="To output the file names will be created without actual creation.")
    args = parser.parse_args()

    log_output = os.path.join(args.dir, "log.txt")
    ill_files = os.path.join(args.dir, "ill_files.txt")
    host_list = read_host_list(args.list)

    proxy_log = os.path.join(args.dir, "proxy_log.txt") if args.proxy is not None else None


    if args.dry_run:
        print("Dry run mode, the file names are listed below:")
        for i in range(args.repeat):
            for host in host_list:
                host = host.strip()
                output_dir = Path("{}/{}".format(args.dir, host))
                output_file_idx = decide_output_file_idx(output_dir)
                # NOTE: In dry-run mode, since the .pcap(ng) files will not be created, we should shift
                # the index with i to get the correct filenames.
                output_file = os.path.join(args.dir, host, "{}_{}.pcapng".format(host, output_file_idx + i))
                print(output_file)
        for host in host_list:
            host = host.strip()
            ssl_keylog_file = Path(f"{args.dir}/{host}/keylog.txt")
            print(ssl_keylog_file)
        print(log_output)
        print(ill_files)
        if proxy_log is not None:
            print(proxy_log)
    else:
        batch_capture(base_dir=args.dir, 
                      host_list=host_list, 
                      iface=args.iface, 
                      repeat=args.repeat, 
                      timeout=args.timeout,
                      ill_files=ill_files,
                      log_output=log_output,
                      proxy_log=proxy_log,
                      proxy=str.lower(args.proxy) if args.proxy is not None else None
                      )