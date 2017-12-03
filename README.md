# CSC-analysis

A python script to analyze traffic from a pcap file to detect the presence of covert storage traffic in a network.

Sample output from my experiments:

regular traffic IPs:
10.10.6.1
10.10.3.1
mixed traffic IPs:
10.10.1.1
10.10.6.1
10.10.3.1
Scanning for covert traffic
Percentage of IP '10.10.1.1': 99.70852562545542
Percentage of IP '10.10.3.1': 0.2914743745445713

From the above output, we can see the IPs present in the sample "regular" traffic. For the mixed traffic, an attacker sending covert storage was added. We can see that the attacker has IP 10.10.1.1, so we hope that the program correctly identifies that IP address as the attacker.

After splitting the suspicious traffic up by time window and comparing it against regular traffic using Kullback–Leibler divergence, we can see that the program correctly identifies IP 10.10.1.1 as sending 99.7% of suspicious traffic.
