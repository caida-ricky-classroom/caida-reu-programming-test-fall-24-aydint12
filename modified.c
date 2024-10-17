#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
// #include <linux/if_ether.h> // Removed because it's causing an error

#define ETHERNET_HEADER_SIZE 14 // Ethernet headers are 14 bytes long

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header; // Changed to struct ip
    int packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Move past the Ethernet header to get to the IP header
        ip_header = (struct ip*)(packet + ETHERNET_HEADER_SIZE); // Adjusted the offset and struct

        // Print the destination IP address
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(ip_header->ip_dst));
    }

    pcap_close(handle);
    return 0;
}
