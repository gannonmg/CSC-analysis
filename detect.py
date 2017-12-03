# Matt Gannon
# Script to analyze pcap files and determine which, if any, IPs are sending covert traffic

from scapy.all import *
import scipy.stats

def createFlagArray(packets):
    # get packets with tcp flags
    flags = []
    for packet in packets:
        if type(packet) is scapy.layers.l2.Ether:
            if TCP in packet:
                flags.append(packet[TCP].flags)
    return flags


def distributeFlags(packets):

    # get packets with tcp flags
    flags = createFlagArray(packets)

    #create distribution
    dist = {}
    for flag in flags:
        if flag in dist:
            dist[flag] += 1.0
        else:
            dist[flag] = 1.0

    for flag in dist:
        dist[flag] = (dist[flag]/len(flags)) * 100

    return dist

# returns IPs present in the pcap files
def getIPs(packets):
    IPs = {}
    for packet in packets:
        if IP in packet:
            if packet[IP].src not in IPs:
                IPs[packet[IP].src] = [packet]
            else:
                IPs[packet[IP].src].append(packet)
    return IPs


# returns a distribution for the dictionary that contains each IP and their packet arrays
def distribute_window(split_packets):
    distribution = {}
    for IP, packets in split_packets.iteritems():
        flag_dist = distributeFlags(packets)
        distribution[IP] = flag_dist

    return distribution

#function to get window_dist and regular_dist to have the same number of contents
#necessary for stats.entropy
def even_lengths(a, b):
    for k in a:
        if k not in b:
            b[k] = 0.0;
    return b

# compares distributions in a window  to regular traffic and returns IPs exibiting suspicous traffic
def compare(window_dist, regular_dist):
    max_entropy = 0.0
    SUSPICIOUS = 5.0    #this float can be adjusted. 5.0 returned with 99% accuracy for my samples
    evil_IP = "NON_SUSPICOUS"
    for IP in window_dist:
        # stats.entropy will only accept lists/dicts of equal length, so add "flag: 0.0" where missing in each dictionary
        window_dist[IP] = even_lengths(regular_dist, window_dist[IP])
        regular_dist = even_lengths(window_dist[IP], regular_dist)

        # when passing two arguments to stats.entropy, returns the KL (Kullback-Leibler) divergence
        # between the arguments
        entropy = scipy.stats.entropy(window_dist[IP].values(), regular_dist.values())
        if entropy > max_entropy:
            max_entropy = entropy
            if max_entropy > SUSPICIOUS:
                evil_IP = IP

    return evil_IP


def analyze(packets, regular_distribution):
    start_time = packets[0].time    #returns time in seconds
    time_window = 20  # in seconds, can be adjusted to preference
    packet_window = []  # array to hold all packets in the __ second time frame
    tracker = []    # array to track suspect IPs

    for packet in packets:
        if TCP in packet:
            current_time = packet.time
            passed_time = current_time - start_time

            if passed_time < time_window:   #populate this time window
                packet_window.append(packet)
            else:   #else, analyze the time window, empty it, and start a new one

                #split the the packets in this window by IP
                split_packets = getIPs(packet_window)

                #get the distribution for this window
                split_distribution = distribute_window(split_packets)

                #compare the split distribution to the regular distribution
                evil_IP = compare(split_distribution, regular_distribution)

                # some time windows don't meet the threshold for supiscious traffic
                # and thus return "NON_SUSPICOUS" instead of an IP,
                # so don't add these to tracker
                if evil_IP is not "NON_SUSPICOUS":
                    tracker.append(evil_IP)

                # empty packet_window for the next loop
                del packet_window[:]

                #start the loop over again from the last packet
                current_time = packet.time
                packet_window.append(packet)

    return tracker

"""
    function to figure out the percentage of each potentially suspicous IP in tracker
    if an IP has a populates a large majority of this array, likely to be sending covert traffic
"""
def final_IP_distribution(tracker):
    dist = {}
    for IP in tracker:
        if IP in dist:
            dist[IP] += 1.0
        else:
            dist[IP] = 1.0

    for flag in dist:
        dist[flag] = (dist[flag]/len(tracker)) * 100
        print "Percentage of IP " + repr(flag) + ": " + repr(dist[flag])

    return dist


def main():

    # read regular traffic pcap file into an array
    regularPackets = rdpcap("regularTraffic.pcap")

    # get the distribution of each flag in the regular pcap file
    regularFlags = distributeFlags(regularPackets)

    # print the IPs present in the regular traffic
    regularIPs = getIPs(regularPackets)
    print "regular traffic IPs: "
    for k in regularIPs:
        print k

    # read the mixed traffic pcap file into an array
    mixedPackets = rdpcap("mixedTraffic.pcap")

    #get the distribution of each flag in the mixed pcap file
    # (not necessary since the packet is split into time windows that are later distributed by flag)
    #mixedFlags = distributeFlags(mixedPackets)

    """
        print the IPs of the mixed traffic
        by comparing to the regular IPs, see that IP 10.10.1.1 is now present
        we know this is the 'attacker' IP from running the experiment,
        so we hope that our program correctly identifies 10.10.1.1 as sending covert traffic
    """
    mixedIPs = getIPs(mixedPackets)
    print "mixed traffic IPs: "
    for k in mixedIPs:
        print k

    print "Scanning for covert traffic"
    tracker = analyze(mixedPackets, regularFlags)
    final_IP_distribution(tracker)



main()
