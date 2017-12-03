# Matt Gannon

from scapy.all import *

def distribute(pcapFile):

    # read pcap file into an array
    packets = rdpcap(pcapFile)
    print "Packets in this pcap file: " + repr(len(packets))

    # get tcp flags
    flags = []
    for packet in packets:
        if TCP in packet:
            #print(packet)
            flags.append(packet[TCP].flags)
            #print(packet[TCP].flags)

    #create distribution
    dist = {}
    for flag in flags:
        if flag in dist:
            dist[flag] += 1.0
        else:
            dist[flag] = 1.0

    for flag in dist:
        dist[flag] = (dist[flag]/len(flags)) * 100
        print "Percentage of " + repr(flag) + "flag: " + repr(dist[flag])

def main():
    print "Distribution of regular traffic"
    regular = distribute("regularTraffic.pcap")
    print "Distribution of mixed traffic"
    regular = distribute("mixedTraffic.pcap")


main()
