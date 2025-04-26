"""
This file aims to count the number of HTTP/2 frame within a given stream among a list of .pcap(ng) files
representing the request to the same website.

For example, there are 100 .pcap(ng) files representing requests to pan.baidu.com, which transfers content
mainly through the domain nd-static.bdstatic.com. Therefore, for each file, we first find TCP streams conveying
HTTP/2 DATA frames.
"""
import pyshark
from WFlib.tools.capture import *
from WFlib.tools.analyzer import *
from pathlib import Path
import json
import argparse

def tls_stat(base_dir_path : Path, SNIs, keylog_file):
    stat = {'host': base_dir_path.name, 'SNIs': SNIs, 'file': []}

    tls_counter = TLSByteCounter()

    for file in sorted(base_dir_path.iterdir()):
        if file.is_file() and file.suffix in ['.pcapng', '.pcap']:
            idx = str(file).split('.')[-2].split('_')[-1]  # Only the index of the filename is needed.
            pkt_count, byte_count = 0, 0
            tcp_stream, _ = h2data_SNI_intersect(file, SNIs, keylog_file=keylog_file, custom_parameters={"-C": "Customized"})
            tcp_stream_filter = stream_extract_filter(tcp_stream, [])
            display_filter = "tls" + " and " + tcp_stream_filter
            if tcp_stream_filter == "":
                continue
            # Strangely, it seems that using TShark introduces many SSL packets, which in Wireshark are actually
            # TCP ones in Wireshark. Therefore, we pass -2 for two-pass dissection to get a more precise result.
            cap = pyshark.FileCapture(input_file=file, display_filter=display_filter, 
                                      custom_parameters=["-C", "Customized", "-2"])
            for pkt in cap:
                try:
                    byte_count += tls_counter.packet_count(pkt)
                    pkt_count += 1
                except Exception as e:
                    print(f"{file.name} raises Exception: {e}")
                    continue

            cap.close()
            stat["file"].append((idx, list(tcp_stream), pkt_count, byte_count))


    with open(f"statistics/tls/{base_dir_path.name}.json", "w") as f:
        json.dump(stat, f)


def tcp_stat(base_dir_path : Path, SNIs, keylog_file):
    stat = {'host': base_dir_path.name, 'SNIs': SNIs, 'file': []}

    tcp_counter = TCPByteCounter()

    for file in sorted(base_dir_path.iterdir()):
        if file.is_file() and file.suffix in ['.pcapng', '.pcap']:
            idx = str(file).split('.')[-2].split('_')[-1]  # Only the index of the filename is needed.
            pkt_count, byte_count = 0, 0

            tcp_stream, _ = h2data_SNI_intersect(file, SNIs, keylog_file=keylog_file, custom_parameters={"-C": "Customized"})
            tcp_stream_filter = stream_extract_filter(tcp_stream, [])
            display_filter = tcp_stream_filter
            if tcp_stream_filter == "":
                continue
            cap = pyshark.FileCapture(input_file=file, display_filter=display_filter,
                                      custom_parameters={"-C": "Customized"})
            for pkt in cap:
                byte_count += tcp_counter.packet_count(pkt)
                pkt_count += 1

            cap.close()
            stat["file"].append((idx, list(tcp_stream), pkt_count, byte_count))


    with open(f"statistics/tcp/{base_dir_path.name}.json", "w") as f:
        json.dump(stat, f)


# def http2_stat(base_dir_path : Path, SNIs, keylog_file):
#     stat = {'host': base_dir_path.name, 'SNIs': SNIs, 'file': []}

#     http2_counter = HTTP2ByteCounter()

#     for file in sorted(base_dir_path.iterdir()):
#         if file.is_file() and file.suffix in ['.pcapng', '.pcap']:
#             idx = str(file).split('.')[-2].split('_')[-1]  # Only the index of the filename is needed.
#             pkt_count, byte_count = 0, 0

#             tcp_stream, _ = h2data_SNI_intersect(file, SNIs, keylog_file=keylog_file, custom_parameters={"-C": "Customized"})
#             tcp_stream_filter = stream_extract_filter(tcp_stream, [])
#             display_filter = "http2" + " and " + tcp_stream_filter
#             if tcp_stream_filter == "":
#                 print(f"Warning: {file.name} does not have satisfying TCP stream.")
#                 continue
#             cap = pyshark.FileCapture(input_file=file, display_filter=display_filter,
#                                       custom_parameters={"-C": "Customized"},
#                                       override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
#             for pkt in cap:
#                 byte_count += http2_counter.count(pkt)
#                 pkt_count += 1

#             cap.close()
#             stat["file"].append((idx, list(tcp_stream), pkt_count, byte_count))


#     with open(f"statistics/http2/{base_dir_path.name}.json", "w") as f:
#         json.dump(stat, f)

def http2_stat(base_dir_path : Path, SNIs, keylog_file):
    http2_stat = {'host': base_dir_path.name, 'SNIs': SNIs, 'file': []}
    tls_stat = {'host': base_dir_path.name, 'SNIs': SNIs, 'file': []}
    tcp_stat = {'host': base_dir_path.name, 'SNIs': SNIs, 'file': []}

    counter = CaptureCounter(TCPByteCounter(), TLSByteCounter(), HTTP2ByteCounter())

    for file in sorted(base_dir_path.iterdir()):
        if file.is_file() and file.suffix in ['.pcapng', '.pcap']:
            idx = str(file).split('.')[-2].split('_')[-1]  # Only the index of the filename is needed.
            tcp_stream, _ = h2data_SNI_intersect(file, SNIs, keylog_file=keylog_file, 
                                                 custom_parameters=["-C", "Customized", "-2"])
            tcp_stream_filter = stream_extract_filter(tcp_stream, [])
            if tcp_stream_filter == "":
                print(f"Warning: {file.name} does not have satisfying TCP stream.")
                continue
            cap = pyshark.FileCapture(input_file=file, display_filter=tcp_stream_filter,
                                      custom_parameters=["-C", "Customized", "-2"],
                                      override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
            try:
                result = counter.count(cap)
            except AttributeError as e:
                print(f"{file.name} raises AttributeError: {e}")
                raise AttributeError()

            cap.close()

            http2_stat["file"].append((idx, list(tcp_stream), result['http2'][0], result['http2'][1]))
            tls_stat["file"].append((idx, list(tcp_stream), result['tls'][0], result['tls'][1]))
            tcp_stat["file"].append((idx, list(tcp_stream), result['tcp'][0], result['tcp'][1]))


    with open(f"statistics/http2/{base_dir_path.name}.json", "w") as f:
        json.dump(http2_stat, f)

    with open(f"statistics/tls/{base_dir_path.name}.json", "w") as f:
        json.dump(tls_stat, f)

    with open(f"statistics/tcp/{base_dir_path.name}.json", "w") as f:
        json.dump(tcp_stat, f)

def http3_stat(base_dir_path : Path, SNIs, keylog_file):
    http3_stat = {'host': base_dir_path.name, 'SNIs': SNIs, 'file': []}
    quic_stat = {'host': base_dir_path.name, 'SNIs': SNIs, 'file': []}
    udp_stat = {'host': base_dir_path.name, 'SNIs': SNIs, 'file': []}

    counter = CaptureCounter(UDPByteCounter(), QUICByteCounter(), HTTP3ByteCounter())

    for file in sorted(base_dir_path.iterdir()):
        if file.is_file() and file.suffix in ['.pcapng', '.pcap']:
            idx = str(file).split('.')[-2].split('_')[-1]  # Only the index of the filename is needed.

            _, udp_stream = h3data_SNI_intersect(file, SNIs, keylog_file=keylog_file, 
                                                 custom_parameters=["-C", "Customized", "-2"])
            udp_stream_filter = stream_extract_filter([], udp_stream)
            if udp_stream_filter == "":
                print(f"Warning: {file.name} does not have satisfying UDP stream.")
                continue
            cap = pyshark.FileCapture(input_file=file, display_filter=udp_stream_filter,
                                      custom_parameters=["-C", "Customized", "-2"],
                                      override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
            
            result = counter.count(cap)

            cap.close()

            http3_stat["file"].append((idx, list(udp_stream), result['http3'][0], result['http3'][1]))
            quic_stat["file"].append((idx, list(udp_stream), result['quic'][0], result['quic'][1]))
            udp_stat["file"].append((idx, list(udp_stream), result['udp'][0], result['udp'][1]))


    with open(f"statistics/http3/{base_dir_path.name}.json", "w") as f:
        json.dump(http3_stat, f)

    with open(f"statistics/quic/{base_dir_path.name}.json", "w") as f:
        json.dump(quic_stat, f)

    with open(f"statistics/udp/{base_dir_path.name}.json", "w") as f:
        json.dump(udp_stat, f)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument("-d", "--dir", default="exp/normal_capture", type=str, help="The base dir for statistics.")
    parser.add_argument("--host", required=True, type=str, help="The host to analyze.")
    parser.add_argument("-s", "--sni", required=True, type=str, help="The domain to analyze.")
    parser.add_argument("-k", "--keylog", type=str, default=None, help="Path to keylog file")
    parser.add_argument("-p", "--protocol", type=str, default="http2", help="Protocol to analyze")
    args = parser.parse_args()
    
    base_dir = f"{args.dir}/{args.host}"
    base_dir_path = Path(base_dir)
    keylog_file = f"{base_dir}/keylog.txt" if args.keylog is None else args.keylog
    SNIs = [args.sni]
    if not base_dir_path.exists():
        print("Invalid base directory.")
        exit(1)

    if args.protocol == "http2":
        http2_stat(base_dir_path, SNIs, keylog_file)
    elif args.protocol == "http3":
        http3_stat(base_dir_path, SNIs, keylog_file)
    else:
        print("Invalid protocol.")