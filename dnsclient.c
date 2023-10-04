#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dnsmessage.h"

#define	BUFLEN 512
#define	LENGTH 255


void error(char *msg, int code) {
	printf("%s\n", msg);
	exit(code);
}


void logMessageEntry(char *message) {
	FILE *file = fopen("message.log", "a+");
	if (file == NULL)
		error("Error opening message.log file!", -2);

	int i;
	for (i = 0; i < BUFLEN; i++)
		fprintf(file, "%02X ", message[i] & 0xFF); // print in hex format
	fprintf(file, "\n");

	fclose(file);
}


int getType(char *str) {
	int type;

	if (strcmp(str, "A") == 0)
		type = A;
	else if (strcmp(str, "NS") == 0)
		type = NS;
	else if (strcmp(str, "CNAME") == 0)
		type = CNAME;
	else if (strcmp(str, "MX") == 0)
		type = MX;
	else if (strcmp(str, "SOA") == 0)
		type = SOA;
	else if (strcmp(str, "TXT") == 0)
		type = TXT;
	else if (strcmp(str, "PTR") == 0)
		type = PTR;
	else
		error("Invalid command!", 1);

	return type;
}


char* getTypeFromInteger(int type) {
	char *queryType = (char*)calloc(5, sizeof(char));

	if (type == A)
		strcpy(queryType, "A");
	else if (type == NS)
		strcpy(queryType, "NS");
	else if (type == CNAME)
		strcpy(queryType, "CNAME");
	else if (type == MX)
		strcpy(queryType, "MX");
	else if (type == SOA)
		strcpy(queryType, "SOA");
	else if (type == TXT)
		strcpy(queryType, "TXT");
	else if (type == PTR)
		strcpy(queryType, "PTR");

	return queryType;
}


/* Function that inverts an ip and adds ".in-addr.arpa" at the end */
char* convertIPToDNSFormat(char *domain) {
	// +13 because of the ".in-addr.arpa" at the end
	char *dnsDomain = (char*)calloc(strlen(domain) + 13, sizeof(char)), *token;

	token = strtok(domain, ".");
	sprintf(dnsDomain, "%s.", token);

	while (1) {
		token = strtok(NULL, ".");
		if (token == NULL)
			break;

		int i, nr = strlen(token);

		for (i = strlen(dnsDomain) - 1; i >= 0; i--)
			dnsDomain[i + nr + 1] = dnsDomain[i];

		for (i = 0; i < nr; i++)
			dnsDomain[i] = token[i];
		dnsDomain[nr] = '.';
	}

	strcat(dnsDomain, "in-addr.arpa");

	return dnsDomain;
}


/* Function that transforms a domain name from "www.google.com" format to "3www6google3com" format */
char* normalToDNSFormat(char *domain) {
	char *dnsDomain = (char*)calloc(strlen(domain) + 2, sizeof(char)), *token;

	token = strtok(domain, ".");
	dnsDomain[0] = strlen(token);
	sprintf(dnsDomain + 1, "%s", token);

	while (1) {
		token = strtok(NULL, ".");
		if (token == NULL)
			break;

		dnsDomain[strlen(dnsDomain)] = strlen(token);
		sprintf(dnsDomain + strlen(dnsDomain), "%s", token);
	}

	return dnsDomain;
}


/* Function that transforms a domain name from "3www6google3com" format to "www.google.com" format */
int dnsToNormalFormat(char *message, int nr, char *domain) {
	int i, j = 0, n, size, offset = 0;

	while (message[nr] != '\0') {
		// extract first 2 bits to check if we are dealing with a pointer
		memcpy(&n, message + nr, 2);
		n = htons(n);

		// if n >= 49152 then the first two bits are set
		if (n >= 49152) {
			dnsToNormalFormat(message, n - 49152, domain + j);
			return offset + 2;
		}

		// find out how many letters are coming after
		size = message[nr++];
		offset++;

		for (i = 0; i < size; i++) {
			domain[j++] = message[nr++];
			offset++;
		}

		domain[j++] = '.';
	}

	// null terminator at the end
	domain[j] = '\0';
	offset++;

	return offset;
}


int writeRRdataToFile(FILE *file, char *message, int offset, char *str, char *queryType, int nrRR, int size_rr, int length_rr) {
	int type = getType(queryType), i;

	if (type == A) {
		// IPv4 address (4 bytes)
		unsigned char ip[4];

		for (i = 0; i < nrRR; i++) {
			memset(ip, 0, 4);
			strncpy(ip, message + offset, length_rr);

			fprintf(file, "%s\tIN\t%s\t%d.%d.%d.%d\n", str, queryType, ip[0], ip[1], ip[2], ip[3]);

			offset += length_rr;
			if (i != nrRR - 1)
				offset += size_rr;
		}

		fprintf(file, "\n");
	}
	else if (type == NS) {
		char nameServer[LENGTH];

		for (i = 0; i < nrRR; i++) {
			memset(nameServer, 0, LENGTH);

			// nameserver comes in "3www6google3com" format, so we need to convert it back to normal format
			offset += dnsToNormalFormat(message, offset, nameServer);

			fprintf(file, "%s\tIN\t%s\t%s\n", str, queryType, nameServer);

			if (i != nrRR - 1)
				offset += size_rr;
		}

		fprintf(file, "\n");
	}
	else if (type == CNAME) {
		char primaryName[LENGTH];
		memset(primaryName, 0, LENGTH);

		offset += dnsToNormalFormat(message, offset, primaryName);

		fprintf(file, "%s\tIN\t%s\t%s\n\n", str, queryType, primaryName);
	}
	else if (type == MX) {
		int pref;
		char mailExchange[LENGTH];

		for (i = 0; i < nrRR; i++) {
			memset(mailExchange, 0, LENGTH);

			// at first two bytes we have a number named preferences
			memcpy(&pref, message + offset, 2);
			pref = ntohs(pref);
			offset += 2;

			// then we have a domain name
			offset += dnsToNormalFormat(message, offset, mailExchange);

			fprintf(file, "%s\tIN\t%s\t%d\t%s\n", str, queryType, pref, mailExchange);

			if (i != nrRR - 1)
				offset += size_rr;
		}

		fprintf(file, "\n");
	}
	else if (type == SOA) {
		char primarySource[LENGTH], mailbox[LENGTH];
		int serial, refresh, retry, expire, minimum;

		for (i = 0; i < nrRR; i++) {
			memset(primarySource, 0, LENGTH);
			memset(mailbox, 0, LENGTH);

			// following the format specified in the RFC
			offset += dnsToNormalFormat(message, offset, primarySource);
			offset += dnsToNormalFormat(message, offset, mailbox);

			memcpy(&serial, message + offset, sizeof(int));
			serial = ntohl(serial);
			offset += sizeof(int);

			memcpy(&refresh, message + offset, sizeof(int));
			refresh = ntohl(refresh);
			offset += sizeof(int);

			memcpy(&retry, message + offset, sizeof(int));
			retry = ntohl(retry);
			offset += sizeof(int);

			memcpy(&expire, message + offset, sizeof(int));
			expire = ntohl(expire);
			offset += sizeof(int);

			memcpy(&minimum, message + offset, sizeof(int));
			minimum = ntohl(minimum);
			offset += sizeof(int);

			fprintf(file, "%s\tIN\t%s\t%s\t%s\t%i\t%i\t%i\t%i\t%i\n", str, queryType, primarySource, mailbox, serial, refresh, retry, expire, minimum);

			if (i != nrRR - 1)
				offset += size_rr;
		}

		fprintf(file, "\n");
	}
	else if (type == TXT) {
		unsigned char *text = (unsigned char*) malloc((length_rr - 1) * sizeof(char));

		for (i = 0; i < nrRR; i++) {
			// we need to jump one character
			memcpy(text, message + offset + 1, length_rr - 1);

			fprintf(file, "%s\tIN\t%s\t%s\n", str, queryType, text);

			if (i != nrRR - 1)
				offset += size_rr;
		}

		fprintf(file, "\n");
	}
	else if (type == PTR) {
		char domain[LENGTH];
		memset(domain, 0, LENGTH);

		offset += dnsToNormalFormat(message, offset, domain);

		fprintf(file, "%s\tIN\t%s\t%s\n\n", str, queryType, domain);
	}

	return offset;
}


void writeResponse(char *message, int nr, char *dnsServer, char *domain, char *queryType) {
	FILE *file = fopen("dns.log", "a+");
	if (file == NULL)
		error("Error opening dns.log file", -2);

	fprintf(file, "; %s - %s %s\n\n", dnsServer, domain, queryType);

	dns_header_t *header = (dns_header_t*)malloc(sizeof(dns_header_t));

	memset(header, 0, sizeof(header));
	memcpy(header, message, sizeof(dns_header_t));

	// check if we have an error in the answer received from the DNS server
	if (header->rcode != 0)
		error("\nError in the answer received from the DNS server!", -5);

	dns_rr_t *rr = (dns_rr_t*)malloc(sizeof(dns_rr_t));
	int size_rr, length_rr, offset;

	char *str = (char*)malloc(LENGTH * sizeof(char));

	// ANSWER section
	int ans_sec = ntohs(header->ancount);

	if (ans_sec > 0) {
		fprintf(file, ";; ANSWER SECTION:\n");

		memset(str, 0, LENGTH);
		// decode domain name received from server
		offset = dnsToNormalFormat(message, nr, str);

		size_rr = offset + sizeof(dns_rr_t) - 2;
		memcpy(rr, message + nr + offset, sizeof(dns_rr_t) - 2);
		nr += size_rr;

		// find what type of Resource Record we have
		char *queryType = getTypeFromInteger(ntohs(rr->type));
		// length of the data of this Resource Record
		length_rr = ntohs(rr->rdlength);

		nr = writeRRdataToFile(file, message, nr, str, queryType, ans_sec, size_rr, length_rr);
	}

	// AUTHORITY section (has same format as ANSWER section)
	int auth_sec = ntohs(header->nscount);

	if (auth_sec > 0) {
		fprintf(file, ";; AUTHORITY SECTION:\n");

		memset(str, 0, LENGTH);
		// decode domain name received from server
		offset = dnsToNormalFormat(message, nr, str);

		size_rr = offset + sizeof(dns_rr_t) - 2;
		memcpy(rr, message + nr + offset, sizeof(dns_rr_t) - 2);
		nr += size_rr;

		char *queryType = getTypeFromInteger(ntohs(rr->type));
		length_rr = ntohs(rr->rdlength);

		nr = writeRRdataToFile(file, message, nr, str, queryType, auth_sec, size_rr, length_rr);
	}

	// ADDITIONAL section (has same format as ANSWER section)
	int add_sec = ntohs(header->arcount);

	if (add_sec > 0) {
		fprintf(file, ";; ADDITIONAL SECTION:\n");

		memset(str, 0, LENGTH);
		// decode domain name received from server
		offset = dnsToNormalFormat(message, nr, str);

		size_rr = offset + sizeof(dns_rr_t) - 2;
		memcpy(rr, message + nr + offset, sizeof(dns_rr_t) - 2);
		nr += size_rr;

		char *queryType = getTypeFromInteger(ntohs(rr->type));
		length_rr = ntohs(rr->rdlength);

		nr = writeRRdataToFile(file, message, nr, str, queryType, add_sec, size_rr, length_rr);
	}

	fprintf(file, "\n");
	fclose(file);
}


char* buildQuery(char *domain, int type, int dimension) {
	int nr;
	char *query = (char*)calloc(dimension, sizeof(char));
	dns_header_t *header = (dns_header_t*)malloc(sizeof(dns_header_t));
	memset(header, 0, sizeof(header));
	char *dnsDomain;

	// set flags in the header
	header->id = htons(1);
	header->rd = 1;
	header->qdcount = htons(1);

	memcpy(query, header, sizeof(dns_header_t));

	if (type != PTR)
		dnsDomain = normalToDNSFormat(domain);
	else {
		char *ip = convertIPToDNSFormat(domain);
		dnsDomain = normalToDNSFormat(ip);
	}

	// add a null termination character between domain and question
	nr = strlen(dnsDomain) + 1;
	memcpy(query + sizeof(dns_header_t), dnsDomain, nr);

	dns_question_t *question = (dns_question_t*)malloc(sizeof(dns_question_t));

	// class 1 for Internet
	question->qclass = htons(1);
	question->qtype = htons(type);
	memcpy(query + sizeof(dns_header_t) + nr, question, sizeof(dns_question_t));

	return query;
}


int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("Usage: %s <domain name or IP address> <record type>\n", argv[0]);
		return -1;
	}

	int queryType = getType(argv[2]), dimension, nr = 0;
	struct sockaddr_in serv_address;
	int sockfd, port = 53, size = sizeof(serv_address);
	char dnsServer[255], buffer[BUFLEN];
	char *dnsQuery;

	FILE *dnsFile = fopen("servers.conf", "r");
	if (dnsFile == NULL)
		error("Error opening servers.conf file!", -2);

	dimension = queryType != PTR ? (strlen(argv[1]) + 2) : (strlen(argv[1]) + 15);
	dimension = dimension + sizeof(dns_header_t) + sizeof(dns_question_t);

	char *domain = (char*)malloc(strlen(argv[1]) * sizeof(char));
	strcpy(domain, argv[1]);

	// build query to send to the DNS server
	dnsQuery = buildQuery(domain, queryType, dimension);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		error("Error opening socket for the DNS server!", -3);

	// timeout 10 seconds to wait for a response
	struct timeval time;
	time.tv_sec = 10;
	time.tv_usec = 0;

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(time)) < 0)
		error("Error setting timeout for the socket that communicates with the DNS server!", -4);

	while (fgets(dnsServer, 255, dnsFile) != NULL) {
		// lines that start with '#' are comments
		if (dnsServer[0] == '#' || dnsServer[0] == '\n')
			continue;

		dnsServer[strlen(dnsServer) - 1] = '\0';
		printf("Connecting to the DNS server %s ...\n", dnsServer);

		memset(&serv_address, 0, sizeof(serv_address));
		serv_address.sin_family = AF_INET;
		serv_address.sin_port = htons(port);
		inet_aton(dnsServer, &serv_address.sin_addr);

		if (connect(sockfd, (struct sockaddr*)&serv_address, sizeof(serv_address)) < 0) {
			printf("Connection failed!\n\n");
			continue;
		}

		printf("Connection successful!\n\nSending query ... (%i bytes)\n", dimension);

		int n = sendto(sockfd, dnsQuery, dimension, 0, (struct sockaddr*)&serv_address, sizeof(serv_address));
		if (n < 0) {
			printf("Error sending query to the DNS server!\n\n");
			continue;
		}

		memset(buffer, 0, BUFLEN);

		n = recvfrom(sockfd, buffer, BUFLEN, 0, (struct sockaddr*)&serv_address, (socklen_t*)&size);
		if (n < 0) {
			printf("Error when receiving response from the DNS server!\n\n");
			continue;
		}

		printf("Received response from the DNS server! (%i bytes)\n", n);

		// log query and response in the message.log file
		logMessageEntry(dnsQuery);

		nr = 1;
		break;
	}

	// if nr is still 0 then we could not communicate with any of the DNS servers from the list
	if (nr == 0)
		printf("Could not communicate with any of the DNS servers from the list!\n");
	else
		writeResponse(buffer, dimension, dnsServer, argv[1], argv[2]);

	close(sockfd);
	fclose(dnsFile);

	return 0;
}

