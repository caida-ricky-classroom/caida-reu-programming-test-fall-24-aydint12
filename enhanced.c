#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
// #include <linux/if_ether.h> // Removed because it's causing an error

#define ETHERNET_HEADER_SIZE 14 // Ethernet headers are 14 bytes long
#define OCTET_RANGE 256 // There are 256 possible values for the last octet (0-255)

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header;
    int last_octet_count[OCTET_RANGE] = {0}; // Array to store counts for each last octet value

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
        ip_header = (struct ip*)(packet + ETHERNET_HEADER_SIZE); // Move past Ethernet header

        // Convert the destination address from network byte order to host byte order
        unsigned long dest_ip = ntohl(ip_header->ip_dst.s_addr);

        // Extract the last octet
        unsigned char last_octet = dest_ip & 0xFF;

        // Increment the count for this last octet
        last_octet_count[last_octet]++;
    }

    pcap_close(handle);

    // Print the counts for each last octet value
    for (int i = 0; i < OCTET_RANGE; i++) {
        if (last_octet_count[i] > 0) {
            printf("Last octet %d: %d\n", i, last_octet_count[i]);
        }
    }

    return 0;
}
