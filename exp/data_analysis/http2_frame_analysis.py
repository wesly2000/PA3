"""
This file aims to count the number of HTTP/2 frame within a given stream among a list of .pcap(ng) files
representing the request to the same website.

For example, there are 100 .pcap(ng) files representing requests to pan.baidu.com, which transfers content
mainly through the domain nd-static.bdstatic.com. Therefore, for each file, we first find TCP streams conveying
HTTP/2 DATA frames.
"""

'''
TODO: Find proper TCP stream
TODO: Count HTTP/2 Frame and draw the bin graph.
'''