/*
* Traffic Classifier
* 
* Abstract
* 		This Program is designed for traffic classification in Home Gateway (HG).
* 
* Description 
* 		This program classifies network traffics into flows using 5-tuple structure (Source/Destination IP address, Source/Destination Port Number, Protocol ID).
* 		After classifying traffics into flows, flows are analyzed and identified for which applications (or application protocol).
* 		Then, this program applies traffic rules into home gateway according to flow's contents characteristics.
* 
* Ex) There are traffics such as video streaming, VoIP, file download in home network. then home gateway differentially manage trafifcs according to content characteristics.  
*/
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include 
// Global variables
unsigned long int total=0;
ipAddr[256][16];

// Flow
typedef struct FlowNode
{
	char *addr;
	unsigned short int srcPort;
	unsigned short int dstPort;
	unsigned long int uplink; // Throughput
	unsigned long int downlink; // Throughput
	unsigned short int app; // Unknown (0), DASH[UHD] (1), DASH[No UHD] (2), VoIP (3), File download (4)
	struct FlowNode *next;
} FlowNode;

// Flow head
FlowNode* head;

// Create, Insert, Remove, Search function for flow management
FlowNode *create_node(char *addr)
{
	// Allocate memory for flow node
	FlowNode *new_flow;
	new_flow = (FlowNode *)malloc(sizeof(FlowNode));
	if ( new_flow == NULL) {
		error("Memory allocation error");
	}
	
	// Initialization for flow node
	new_flow->addr = addr;
	uplink = 0;
	downlink = 0;
	app = 0;
}

FlowNode *search_flow (FlowNode *head, char *addr)
{
	FlowNode *p;
	p = head;
	while( p != NULL ){
		if ( !strcmp( inet_ntoa(p->addr), addr ) ){
			return p;
		}
		p = p->next;
	}
}


// ********************************************************************************************************************* //

// Main
int main(int argc, char const *argv[])
{
	// Network interface pointers and handler for packet capture
	pcap_if_t *allDev, *dev;
	pcap_t *pcapHandler;

	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;

	// Initialize IP Arrays 192.168.1.0 - 192.168.1.255
	for ( int i = 0; i < 256; ++i ){
		sprintf(ipAddr[i], "192.168.1.%d", i);
		printf("%s\n", ipAddr[i]);
	}

	// 1st. Get available network interfaces for packet capture
	printf("Finding available network interfaces...");
	if ( pcap_findalldevs(&allDev ,errbuf) )
	{
		printf("Error finding devs : %s" ,errbuf);
		exit(1);
	}

	// Show the available devices
	printf("\nAvailable devs are :\n");
	for (dev = allDev ; dev != NULL ; dev = dev->next)
	{
		printf("[%d] %s - %s\n", count, dev->name, dev->description);
		if(dev->name != NULL)
		{
			strcpy(devs[count], dev->name);
		}
		count++;
	}

	// 2nd. Select one interface of available interfaces to capture packet
	printf("Enter the number of the dev you want to sniff : ");
	scanf("%d", &n);

	devname = devs[n];

	// 3rd. Open the selected network interface
	printf("Opening dev %s for sniffing ... " , devname);
	pcapHandler = pcap_open_live(devname, 65536, 1, 0, errbuf);
	if(pcapHandler == NULL)
	{
		fprintf(stderr, "Couldn't open dev %s : %s\n", devname, errbuf);
		exit(1);
	}
	printf("Done\n");

	// Record fragment information
	logfile = fopen("log.json","w");
	if(logfile == NULL)
	{
		printf("Unable to create file.");
	}

	// Process packet using callback function
	pcap_loop(pcapHandler, -1, process_packet, NULL);
	
	fclose(logfile);

	return 0;
}

// Flow update
void flow_update()
{

}
// Process packet 
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	// Collect packet information
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)( buffer + sizeof(struct ethhdr) );
	iphdrlen = iph -> ihl*4;
	
	struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->th_off*4;
	int size = header->len;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	// Check flow list
	for ( int i = 0; i < 256; ++i ){
		if ( !strcmp( inet_ntoa(source.sin_addr), ipAddr[i]) ){ // Uplink 
			if( search_flow(head, ipAddr[i]) != NULL ){ 
				// Todo: Update flow information
			}
			else{
				// Todo: Create flow node and Update flow information
			}
		}
		else if ( !strcmp( inet_ntoa(dest.sin_addr), ipAddr[i]) ){ // Downlink
			if( search_flow(head, ipAddr[i]) != NULL ){ 
				// Todo: Update flow information

			}
			else{
				// Todo: Create flow node and Update flow information
			}
		}
	}
}

