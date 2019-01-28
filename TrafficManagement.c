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

// Head flow and current flow
FlowNode* head = NULL;
FlowNode* curr = NULL;

// Create, Insert, Remove, Search function for flow management
FlowNode *create_flow(char *addr)
{
	// Allocate memory for flow node
	FlowNode *new_flow;
	new_flow = (FlowNode *)malloc(sizeof(FlowNode));
	if ( new_flow == NULL) {
		error("Memory allocation error");
	}

	// Attach new node to end of flow list
	FlowNode *p = head;
	if (p == NULL){ // There is no any flow in Flow list, attach flow node as first node
		head = new_flow;
		new_flow->next = NULL;		
	}

	while ( p != NULL ){

		if ( p->next == NULL ){
			p->next = new_flow;
			new_flow->next = NULL;
		}
		p = p->next;
	}
	
	// Initialization for flow node
	new_flow->addr = addr;
	new_flow->uplink = 0;
	new_flow->downlink = 0;
	new_flow->app = 0;
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

	// Initialize IP Arrays 192.168.1.0 - 192.168.1.255 to implement in HG (10.0.2.0 - 10.0.2.255 for local test)
	for ( int i = 0; i < 256; ++i ){
		//sprintf(ipAddr[i], "192.168.1.%d", i); // for ip for home gateway
		sprintf(ipAddr[i], "10.0.2.%d", i);
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

	// Record results
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
void analyze_flow(FlowNode *flow, char* addr, int packetSize, const u_char *buffer, bool isUplink)
{
	if ( isUplink == true ){ // Uplink
		// Todo: Update basic flow inforamtion EX) Throughput, etc.
		printf("[Uplink]   Currnet Flow Info.\n");
		printf("IP: %s\n", curr->addr);
		printf("Uplink: %d\n", curr->uplink);
		printf("Downlink: %d\n", curr->downlink);
		printf("------------------------------------------------\n");
		// Todo: Analyze flows to identify app used by flow
	}
	else{ // Downlink
		// Todo: Update basic flow's information
		printf("[Downlink] Currnet Flow Info.\n");
		printf("IP: %s\n", curr->addr);
		printf("Uplink: %d\n", curr->uplink);
		printf("Downlink: %d\n", curr->downlink);
		printf("------------------------------------------------\n");
		// Todo: Analyze flows to identify app used by flow
	}
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
			if( (curr = search_flow(head, ipAddr[i])) != NULL ){ 
				// Update flow information
				analyze_flow(ipAddr[i], size, buffer, true);
			}
			else{
				// Create flow node and Update flow information
				create_flow(ipAddr[i]);
				analyze_flow(ipAddr[i], size, buffer, false);
			}
		}
		else if ( !strcmp( inet_ntoa(dest.sin_addr), ipAddr[i]) ){ // Downlink
			if( (curr = search_flow(head, ipAddr[i])) != NULL ){ 
				// Update flow information
				analyze_flow(ipAddr[i], size, buffer, true);
			}
			else{
				// Create flow node and Update flow information
				create_flow(ipAddr[i]);
				analyze_flow(ipAddr[i], size, buffer, false);
			}
		}
	}

	// After flow analysis, we can get flow's application. so, we can do traffic shaping according to flow's applicaiton
	/* Code */
}

