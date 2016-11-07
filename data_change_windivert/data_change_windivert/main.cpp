#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#define MAXBUF  0xFFFF
#define MAX_LEN 100

typedef struct{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

UINT16 TcpheaderChecksum(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header){
	unsigned short *pseudo_tcph = (unsigned short *)tcp_header;
	unsigned short *tempIP;
	unsigned short dataLen = (ntohs(ip_header->Length)) - sizeof(WINDIVERT_IPHDR);
	unsigned short nLen = dataLen;
	unsigned checksum = 0;
	int i = 0;

	tcp_header->Checksum = 0;
	nLen = nLen >> 1;

	for (i = 0; i < nLen; i++)	checksum += *pseudo_tcph++;
	if (dataLen % 2 == 1)		checksum += *pseudo_tcph++ & 0x00ff; //&0xff00

	tempIP = (unsigned short *)(&ip_header->SrcAddr);
	for (i = 0; i < 2; i++)		checksum += *tempIP++;
	tempIP = (unsigned short *)(&ip_header->DstAddr);
	for (i = 0; i < 2; i++)		checksum += *tempIP++;
	checksum += htons(6);			//IP Protocol
	checksum += htons(dataLen);	//tcpLength+dataLen
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	return(~checksum & 0xffff);
}

void dumpPayload(const u_char *payload, int len) {
	if (len <= 0)	return;

	printf("\n       ****** PAYLOAD ******\n");
	for (int i = 0; i < len; i += 16) {
		int cnt = i + 16;
		if (cnt > len)
			cnt = len;
		for (int j = i; j < cnt; j++) {
			u_char tmp = *(payload + j);
			printf("%02x ", tmp);
		}
		for (int j = 1; j <= 55 - 3 * (cnt - i); j++)	printf(" ");
		for (int j = i; j<cnt; j++) {
			char tmp = *(payload + j);
			if ((tmp >= 0x21) && (tmp <= 0x7e))	printf("%c", tmp);
			else								printf(".");
		}
		printf("\n");
	}
	printf("\n\n");

	return;
}

int main(int argc, char **argv) {
	HANDLE handle;          // WinDivert handle
	WINDIVERT_ADDRESS addr; // Packet address
	char packet[MAXBUF];    // Packet buffer
	UINT packetLen;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;

	char* data, *host;
	int i = 0;
	char *modify = "GILBERT";
	char *target = "Michael";
	char *encoding = "gzip";
	char *encoding_space = "    ";

	handle = WinDivertOpen("tcp.DstPort == 80 or tcp.SrcPort == 80", (WINDIVERT_LAYER)0, 0, 0);   // Open some filter
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main capture-modify-inject loop
	while (TRUE) {
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packetLen)) {
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		ip_header = (PWINDIVERT_IPHDR)packet;
		tcp_header = (PWINDIVERT_TCPHDR)((char*)ip_header + (ip_header->HdrLength) * 4);
		data = (char*)((char*)tcp_header + (tcp_header->HdrLength) * 4);

		// find gzip => replace with space
		host = strstr(data, encoding);
		if (host != NULL) {
			memcpy(host, encoding_space, strlen(encoding_space));
			tcp_header->Checksum = TcpheaderChecksum(ip_header, tcp_header);
			host = 0;
		}

		// find target string => replace with other string
		host = strstr(data, target);
		if (host != NULL) {
			printf("found the string...\n");
			memcpy(host, modify, strlen(modify));
			tcp_header->Checksum = TcpheaderChecksum(ip_header, tcp_header);
		}

		if (!WinDivertSend(handle, packet, packetLen, &addr, NULL)) {
			fprintf(stderr, "warning: failed to send packet\n");
			continue;
		}
	}
	WinDivertClose(handle);
}