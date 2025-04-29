from WFlib.tools.capture import *
from WFlib.tools.analyzer import packet_count
import pyshark


baidu_proxied_file = "exp/test_dataset/realworld_dataset/www.baidu.com_proxied.pcapng"
google_file = "exp/test_dataset/realworld_dataset/www.google.com.pcapng"
apple_file = "exp/test_dataset/realworld_dataset/decryption/www.apple.com.pcapng"
tiktok_file = "exp/test_dataset/realworld_dataset/decryption/www.tiktok.com.pcapng"

def test_SNI_extract_1():
    capture = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter="tls.handshake.type == 1")
    SNIs = SNI_extract(capture)

    target = {
        "dns.alidns.com",
        "doh.pub",
        "dns.cloudflare.com",
        "firefox.settings.services.mozilla.com",
        "content-signature-2.cdn.mozilla.net",
        "firefox-settings-attachments.cdn.mozilla.net",
        "dns.twnic.tw"
    }

    assert SNIs == target

    capture.close()

def test_SNI_extract_2():
    capture = pyshark.FileCapture(input_file=google_file, display_filter="tls.handshake.type == 1")
    SNIs = SNI_extract(capture)

    target = {
        "mobile.events.data.microsoft.com",
        "firefox-settings-attachments.cdn.mozilla.net",
        "www.google.com",
        "csp.withgoogle.com",
        "www.gstatic.com",
        "ogads-pa.googleapis.com"
    }

    assert SNIs == target

    capture.close()

def test_stream_number_extract_1():
    capture = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter="tls.handshake.type == 1")
    SNIs = SNI_extract(capture)
    
    tcp_stream_numbers, _ = stream_number_extract(capture=capture, check=lambda pkt: contains_SNI(SNIs, pkt))

    target = {'1', '4', '3', '10', '11', '13', '14', '65', '68', '67', '66', '69', '97', '101', '105', '123'}

    assert tcp_stream_numbers == target

    capture.close()

def test_stream_extract_filter():
    tcp_stream_numbers, udp_stream_numbers = [], []
    display_filter = stream_extract_filter(tcp_stream_numbers, udp_stream_numbers)
    target = ""
    assert display_filter == target

    tcp_stream_numbers, udp_stream_numbers = ['1', '4', '3'], []
    display_filter = stream_extract_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "tcp.stream == 1 or tcp.stream == 4 or tcp.stream == 3"

    tcp_stream_numbers, udp_stream_numbers = [], ['1', '4', '3']
    display_filter = stream_extract_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "udp.stream == 1 or udp.stream == 4 or udp.stream == 3"

    tcp_stream_numbers, udp_stream_numbers = ['1'], ['4', '3']
    display_filter = stream_extract_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "tcp.stream == 1 or udp.stream == 4 or udp.stream == 3"

    assert display_filter == target

def test_stream_exclude_filter_1():
    tcp_stream_numbers, udp_stream_numbers = [], []
    display_filter = stream_exclude_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "(tcp or udp) and not icmp"
    assert display_filter == target

def test_stream_exclude_filter_2():
    tcp_stream_numbers, udp_stream_numbers = ['1', '4', '3'], []
    display_filter = stream_exclude_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "((tcp and tcp.stream != 1 and tcp.stream != 4 and tcp.stream != 3) or udp) and not icmp"

    assert display_filter == target

def test_stream_exclude_filter_3():
    tcp_stream_numbers, udp_stream_numbers = [], ['1', '4', '3']
    display_filter = stream_exclude_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "(tcp or (udp and udp.stream != 1 and udp.stream != 4 and udp.stream != 3)) and not icmp"

    assert display_filter == target

def test_stream_exclude_filter_4():
    tcp_stream_numbers, udp_stream_numbers = ['2', '5'], ['1', '4', '3']
    display_filter = stream_exclude_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "((tcp and tcp.stream != 2 and tcp.stream != 5) or (udp and udp.stream != 1 and udp.stream != 4 and udp.stream != 3)) and not icmp"

    assert display_filter == target

def test_SNI_exclude_filter_1():
    SNIs = read_host_list("exp/data_extract/filter.txt")

    client_hello_capture = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter="tls.handshake.type == 1")
    tcp_stream_numbers, _ = stream_number_extract(capture=client_hello_capture, check=lambda pkt: contains_SNI(SNIs, pkt))
    client_hello_capture.close()

    display_filter = SNI_exclude_filter(baidu_proxied_file, SNIs)

    capture = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter=display_filter)
    for pkt in capture:
        if 'TCP' in pkt:
            assert pkt['TCP'].stream not in tcp_stream_numbers 

    capture.close()

def test_SNI_exclude_filter_2():
    """
    This test covers filtering out TCP streams and UDP streams once their SNI lies in the given
    SNIs set.
    """
    target = 16
    SNIs = ['www.google.com', 'mobile.events.data.microsoft.com']
    display_filter = SNI_exclude_filter(google_file, SNIs)
    cap = pyshark.FileCapture(input_file=google_file, display_filter=display_filter, only_summaries=True, keep_packets=False)
    cnt = packet_count(cap)

    cap.close()
    assert target == cnt

def test_h2data_SNI_intersect_1():
    '''
    This test covers the intersection of SNI and HTTP/2 DATA streams.
    '''
    SNIs = ["is1-ssl.mzstatic.com"]
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    tcp_stream_numbers, _ = h2data_SNI_intersect(file=apple_file, SNIs=SNIs, keylog_file=keylog_file)
    target = {'0'}

    assert tcp_stream_numbers == target

def test_h2data_SNI_intersect_2():
    '''
    This test covers the a non-existent SNI, and the result should be empty.
    '''
    SNIs = ["is1-ssl.mzstatic"]
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    tcp_stream_numbers, _ = h2data_SNI_intersect(file=apple_file, SNIs=SNIs, keylog_file=keylog_file)
    target = set()

    assert tcp_stream_numbers == target

def test_h3data_SNI_intersect_1():
    '''
    This test covers the intersection of SNI and HTTP/3 DATA streams.'
    '''
    SNIs = ["lf16-cdn-tos.tiktokcdn-us.com"]
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    _, udp_stream_numbers = h3data_SNI_intersect(file=tiktok_file, SNIs=SNIs, keylog_file=keylog_file)

    target = {'0'}

    assert udp_stream_numbers == target

def test_h3data_SNI_intersect_2():
    '''
    This test covers the a non-existent SNI, and the result should be empty.
    '''
    SNIs = ["lf16-cdn-tos.tiktokcdn-us."]
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    _, udp_stream_numbers = h3data_SNI_intersect(file=tiktok_file, SNIs=SNIs, keylog_file=keylog_file)

    target = set()

    assert udp_stream_numbers == target

def test_select_stream_with_max_packet_count():
    """
    This test covers the selection of the stream with the maximum packet count.
    """
    tcp_stream_numbers = {'1', '2', '3'}
    result = select_stream(apple_file, tcp_stream_numbers, mapper=packet_count, criteria=max)

    target = {'3'}

    assert result == target
    