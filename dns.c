/* 
 * dns.c - a simple DNS replier
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include "miscutil.h"
#include "dns_parse.h"

#define BUFSIZE 65535

struct __attribute__((__packed__)) dns_answer_a {
    struct dns_answer header;
    unsigned int address;
};

void make_response_bytes_for_a(void *inptr, unsigned int ipaddr) {
    struct dns_answer_a *resp = (struct dns_answer_a *)inptr;
    resp->header.name = htons((unsigned short)0xc00c); // endian swapped already
    resp->header.type = htons((unsigned short)DNS_RECORD_A); // endian swapped already
    resp->header.class = htons((unsigned short)0x0001); // endian swapped already
    resp->header.ttl = htonl(0x0000012b); // not sure how to endian swap
    resp->header.dlen = htons((unsigned short)0x0004); // endian swapped
    
    resp->address = htonl(ipaddr); //
}

struct __attribute__((__packed__)) dns_answer_aaaa {
    struct dns_answer header;
    unsigned char address[16];
};

void make_response_bytes_for_aaaa(void *inptr, unsigned char *ipaddr) {
    struct dns_answer_aaaa *resp = (struct dns_answer_aaaa *)inptr;
    int i;
    
    resp->header.name = htons((unsigned short)0xc00c); // endian swapped already
    resp->header.type = htons((unsigned short)DNS_RECORD_AAAA); // endian swapped already
    resp->header.class = htons((unsigned short)0x0001); // endian swapped already
    resp->header.ttl = htonl(0x0000012b); // not sure how to endian swap
    resp->header.dlen = htons((unsigned short)0x0010); // endian swapped
    
    for (i = 0; i < 16; i++) {
        resp->address[i] = ipaddr[i]; // when copying byte-for-byte, no endian trickery needed
    }
}

void make_response_bytes_for_txt(void *inptr, unsigned char *text, unsigned short textlength) {
    struct dns_answer *resp = (struct dns_answer *)inptr;
    unsigned char *tmp;
    unsigned short i;
    
    resp->name = htons((unsigned short)0xc00c); // endian swapped already
    resp->type = htons((unsigned short)DNS_RECORD_TXT); // endian swapped already
    resp->class = htons((unsigned short)0x0001); // endian swapped already
    resp->ttl = htonl(0x0000012b); // not sure how to endian swap
    resp->dlen = htons((unsigned short)textlength); // endian swapped
    
    tmp = (unsigned char *)(&(resp->dlen)) + 2; // skip past short
    
    for (i = 0; i < textlength; i++) {
        tmp[i] = text[i]; // when copying byte-for-byte, no endian trickery needed
    }
}

int main(int argc, char **argv) {
    int sockfd; /* socket */
    int portno; /* port to listen on */
    int clientlen; /* byte size of client's address */
    struct sockaddr_in6 serveraddr; /* server's addr */
    struct sockaddr_in6 clientaddr; /* client addr */
    struct hostent *hostp; /* client host info */
    unsigned char buf[BUFSIZE]; /* message buf */
    char *hostaddrp; /* dotted decimal host addr string */
    int optval; /* flag value for setsockopt */
    int n; /* message byte size */
    
    // self dns stuff
    struct dns_request *test;
    unsigned char *tmp;
    char *temp;
    unsigned short *code;
    int i, offset;
    
    /* 
    * check command line arguments 
    */
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s <port> [input file]\n", argv[0]);
        exit(1);
    }
    
    portno = atoi(argv[1]);
    
    if (argc == 3) {
        printf("Warning: DNS from file not yet implemented\n");
    }
    
    /* 
    * socket: create the parent socket 
    */
    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sockfd < 0) error("ERROR opening socket");
    
    printf("socket open\n");
    
    /* setsockopt: Handy debugging trick that lets 
    * us rerun the server immediately after we kill it; 
    * otherwise we have to wait about 20 secs. 
    * Eliminates "ERROR on binding: Address already in use" error. 
    */
    optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
        (const void *)&optval , sizeof(int));
    
    /*
    * build the server's Internet address
    */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin6_family = AF_INET6;
    serveraddr.sin6_addr.s6_addr = htonl(INADDR_ANY);
    serveraddr.sin6_port = htons((unsigned short)portno);
    
    /* 
    * bind: associate the parent socket with a port 
    */
    if (bind(sockfd, (struct sockaddr *) &serveraddr, 
        sizeof(serveraddr)) < 0) 
        error("ERROR on binding");
    
    printf("bound socket to port\n");
    
    /* 
    * main loop: wait for a datagram, then echo it
    */
    printf("started listening!\n");
    clientlen = sizeof(clientaddr);
    while (1) {
        /*
        * recvfrom: receive a UDP datagram from a client
        */
        bzero(buf, BUFSIZE);
        n = recvfrom(sockfd, buf, BUFSIZE, 0,
            (struct sockaddr *) &clientaddr, &clientlen);
        printf("------------------\n");
        if (n < 0) error("ERROR in recvfrom");
        
        /* 
        * gethostbyaddr: determine who sent the datagram
        */
        hostp = gethostbyaddr((const char *)&clientaddr.sin6_addr.s6_addr, 
                sizeof(clientaddr.sin6_addr.s6_addr), AF_INET);
        /* NOTE: SEE HERE? THIS IS WHERE I STOPPED */
        hostaddrp = inet_ntop(clientaddr.sin6_addr);
        if (hostaddrp == NULL) error("ERROR on inet_ntoa\n");
        
        printf("server received %d byte datagram from %s\n", n, hostaddrp);
        hexDump("recv data", buf, n);
        
        test = (struct dns_request *)buf;
        (test->header).num_questions = ntohs((test->header).num_questions);
        (test->header).num_answers = ntohs((test->header).num_answers);
        
        printf("\tExtracted data: \n");
        printf("\t\tTransaction ID: %hu\n", (test->header).transaction_id);
        printf("\t\tNumber of questions: %hu\n", (test->header).num_questions);
        
        temp = NULL;
        tmp = &(test->data);
        
        for (i = 0; i < (test->header).num_questions; i++) {
            free(temp);
            
            if (tmp - buf > BUFSIZE) { // prevent buffer overflow
                printf("Advanced too much! Malformed packet or possible attack attempt.\n");
                break;
            }
            
            temp = dns_str_convert(tmp);
            printf("\t\tQuery #%d:\n", i+1);
            printf("\t\t\t%s\n", temp);
            offset = strlen(temp) + 1;
            
            code = (unsigned short *)((unsigned char *)tmp + offset);
            *code = ntohs(*code);
            
            printf("\t\t\tType: %s", code_to_str(*code));
            if (*code_to_str(*code) == 'U') printf(" (code %hu)", *code);
            
            tmp += offset + 2 + 2;
            
            puts("");
        }
        
        if (buf[2] & 0x80 || (test->header).num_answers > 0) {
            printf("Weirdly enough, this packet contains an answer.\nJumping out.");
            goto nextOne;
        }
        
        if ((test->header).num_questions == 1) {
            unsigned char *myNewBytes;
            int ip4;
            switch (*code) {
                case DNS_RECORD_ANY:
                case DNS_RECORD_A:
                    printf("Replying!\n");
                    n = 16 + strlen(temp) + 1;
                    
                    // copy memory + response stub for A
                    myNewBytes = calloc(n+sizeof(struct dns_answer_a), sizeof(unsigned char));
                    test = (struct dns_request *)myNewBytes;
                    
                    // switch back to endian-swapped code
                    *code = htons(*code);
                    
                    // copy old stuff
                    memcpy(myNewBytes, buf, n);
                    
                    // format the header
                    (test->header).flags = htons(0x8400); // standard response, no error (endian-swapped) - don't recursively query
                    // questions # is the same
                    (test->header).num_answers = htons(0x0001);
                    (test->header).num_questions = htons(0x0001);
                    (test->header).num_authority = 0;
                    (test->header).num_additional = 0;
                    
                    if (strstr(temp, "0x2f.cf") != NULL) ip4 = 918406927;
                    else ip4 = 3111756784;
                    
                    // throwin the ip response at the right spot
                    make_response_bytes_for_a(myNewBytes+n, ip4);
            
                    // for ip response
                    n += sizeof(struct dns_answer_a);
                    
                    // make_response_bytes_for_ip
                    hexDump("send data", myNewBytes, n);
                    
                    n = sendto(sockfd, myNewBytes, n, 0, (struct sockaddr *) &clientaddr, clientlen);
                    if (n < 0) printf("Failed to reply.\n");
                    free(myNewBytes);
                    break;
                case DNS_RECORD_AAAA:
                    printf("Replying!\n");
                    n = 16 + strlen(temp) + 1;
                    
                    // copy memory + response stub for AAAA
                    myNewBytes = calloc(n+sizeof(struct dns_answer_aaaa), sizeof(unsigned char));
                    unsigned char ip6[16];
                    test = (struct dns_request *)myNewBytes;
                    
                    // switch back to endian-swapped code
                    *code = htons(*code);
                    
                    // copy old stuff
                    memcpy(myNewBytes, buf, n);
                    
                    // format the header
                    (test->header).flags = htons(0x8400); // standard response, no error (endian-swapped) - don't recursively query
                    // questions # is the same
                    (test->header).num_answers = htons(0x0001);
                    (test->header).num_questions = htons(0x0001);
                    (test->header).num_authority = 0;
                    (test->header).num_additional = 0;
                    
                    // throwin the ip response at the right spot
                    inet_pton(AF_INET6, "2a05:dfc7:dfc8:1d7::9428", ip6);
                    make_response_bytes_for_aaaa(myNewBytes+n, ip6);
            
                    // for ip response
                    n += sizeof(struct dns_answer_aaaa);
                    
                    // make_response_bytes_for_ip
                    hexDump("send data", myNewBytes, n);
                    
                    n = sendto(sockfd, myNewBytes, n, 0, (struct sockaddr *) &clientaddr, clientlen);
                    if (n < 0) printf("Failed to reply.\n");
                    free(myNewBytes);
                    break;
                case DNS_RECORD_TXT: // these don't work right now
                    printf("Replying!\n");
                    n = 16 + strlen(temp) + 1;
                    
                    char *response = "\024ohnx's DNS responder\030See d.masonx.ca for info";
                    int resplen = strlen(response);
                    
                    // copy memory + response stub for TXT
                    myNewBytes = calloc(n+sizeof(struct dns_answer) + resplen, sizeof(unsigned char));
                    test = (struct dns_request *)myNewBytes;
                    
                    // switch back to endian-swapped code
                    *code = htons(*code);
                    
                    // copy old stuff
                    memcpy(myNewBytes, buf, n);
                    
                    // format the header
                    (test->header).flags = htons(0x8000); // standard response, no error (endian-swapped) - don't recursively query
                    // questions # is the same
                    (test->header).num_answers = htons(0x0001);
                    (test->header).num_questions = htons(0x0001);
                    (test->header).num_authority = 0;
                    (test->header).num_additional = 0;
                    
                    // throwin the ip response at the right spot
                    make_response_bytes_for_txt(myNewBytes+n, response, (unsigned short)resplen);
            
                    // for ip response
                    n += sizeof(struct dns_answer) + resplen;
                    
                    // make_response_bytes_for_ip
                    hexDump("send data", myNewBytes, n);
                    
                    n = sendto(sockfd, myNewBytes, n, 0, (struct sockaddr *) &clientaddr, clientlen);
                    if (n < 0) printf("Failed to reply.\n");
                    free(myNewBytes);
                    break;
                default:
                    goto error_message;
            }
            free(temp);
            temp = NULL;
            goto nextOne;
        }

        error_message:
        // send no answers
        printf("Replying Error!\n");
        
        // switch back to endian-swapped code
        *code = htons(*code);
        
        // format the header
        (test->header).flags = htons(0x8003); // standard response, not found error (endian-swapped) - don't recursively query
        // questions # is the same
        (test->header).num_answers = 0;
        (test->header).num_questions = htons(0x0001);
        (test->header).num_authority = 0;
        (test->header).num_additional = 0;
        
        // make_response_bytes_for_ip
        hexDump("send data", buf, n);
        
        n = sendto(sockfd, buf, n, 0, (struct sockaddr *) &clientaddr, clientlen);
        if (n < 0) printf("Failed to reply.\n");
        
        nextOne:
        free(temp);
        temp = NULL;
    }
}
