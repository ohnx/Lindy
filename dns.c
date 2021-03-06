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
#include "response_maker.h"
#include "query_records.h"
#include "hashmap.h"

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#define BUFSIZE 65535

int main(int argc, char **argv) {
    int sockfd; /* socket */
    int portno; /* port to listen on */
    socklen_t clientlen; /* byte size of client's address */
    struct sockaddr_in6 serveraddr; /* server's addr */
    struct sockaddr_in6 clientaddr; /* client addr */
    unsigned char buf[BUFSIZE]; /* message buf */
    char clientip[INET6_ADDRSTRLEN]; /* dotted decimal host addr string */
    int optval; /* flag value for setsockopt */
    int n; /* message byte size */
    hashmap *h;
    
    /* self dns stuff */
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
    serveraddr.sin6_addr = in6addr_any;
    serveraddr.sin6_port = htons((unsigned short)portno);
    
    /* 
    * bind: associate the parent socket with a port 
    */
    if (bind(sockfd, (struct sockaddr *) &serveraddr, 
        sizeof(serveraddr)) < 0) 
        error("ERROR on binding");
    
    printf("bound socket to port\n");
    
    /**
     * Init hashmap
     */
    h = hashmap_new();
    hashmap_put(h, "test", (void *)"meme");
    if (1) {
        struct dns_record myRec;
        char *testresponse;
        
        myRec.rtype = DNS_RECORD_A;
        myRec.data_len = sizeof(struct dns_answer_a);
        myRec.data = calloc(1, sizeof(struct dns_answer_a));
        make_response_bytes_for_a(myRec.data, 3111756784);
        add_record(h, "test.masonx.ca", myRec);
        
        testresponse = "\024ohnx's DNS responder\030See d.masonx.ca for info";
        myRec.rtype = DNS_RECORD_TXT;
        myRec.data_len = sizeof(struct dns_answer_txt) + strlen(testresponse);
        myRec.data = calloc(1, sizeof(struct dns_answer_txt) + strlen(testresponse) + 1);
        make_response_bytes_for_txt(myRec.data, (unsigned char *)testresponse, strlen(testresponse));
        add_record(h, "test.masonx.ca", myRec);
    }
    
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

        inet_ntop(AF_INET6, &(clientaddr.sin6_addr), clientip, sizeof(clientip));
        
        printf("server received %d byte datagram from %s\n", n, strncmp(clientip, "::ffff:", 7)?clientip:&clientip[7]);
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
            
            if (tmp - buf > BUFSIZE) { /* prevent buffer overflow */
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
        }
        
        if (buf[2] & 0x80 || (test->header).num_answers > 0) {
            printf("Weirdly enough, this packet contains an answer.\nJumping out.");
            goto nextOne;
        }
        
        puts("");
        
        if ((test->header).num_questions == 1) {
            unsigned char *myNewBytes;
            struct dns_record testrecord;
            char *dnsreq;

            printf("Replying!\n");
            
            /* search for query */
            
            n = 16 + strlen(temp) + 1;
            
            dnsreq = dns_str_convert(&(test->data));
            printf("Extracted dnsreq = %s\n", dnsreq);
            testrecord = get_record(h, dnsreq, *code);
            free(dnsreq);
            
            if (testrecord.rtype == DNS_RECORD_UNKNOWN) goto error_message;
            
            /* copy memory + response stub for A */
            myNewBytes = calloc(n+testrecord.data_len, sizeof(unsigned char));
            test = (struct dns_request *)myNewBytes;
            
            /* switch back to endian-swapped code */
            *code = htons(*code);
            
            /* copy old stuff */
            memcpy(myNewBytes, buf, n);
            
            /* format the header */
            (test->header).flags = htons(0x8400); /* standard response, no error (endian-swapped) - don't recursively query */
            /* questions # is the same */
            (test->header).num_answers = htons(0x0001);
            (test->header).num_questions = htons(0x0001);
            (test->header).num_authority = 0;
            (test->header).num_additional = 0;
            
            memcpy(myNewBytes+n, testrecord.data, testrecord.data_len);
            
            /* for ip response */
            n += testrecord.data_len;
            
            /* make_response_bytes_for_ip */
            hexDump("send data", myNewBytes, n);
            
            n = sendto(sockfd, myNewBytes, n, 0, (struct sockaddr *) &clientaddr, clientlen);
            if (n < 0) printf("Failed to reply.\n");
            free(myNewBytes);
            
            free(temp);
            temp = NULL;
            goto nextOne;
        }

        error_message:
        /* send no answers */
        printf("Replying Error!\n");
        
        /* switch back to endian-swapped code */
        *code = htons(*code);
        
        /* format the header */
        (test->header).flags = htons(0x8003); /* standard response, not found error (endian-swapped) - don't recursively query */
        /* questions # is the same */
        (test->header).num_answers = 0;
        (test->header).num_questions = htons(0x0001);
        (test->header).num_authority = 0;
        (test->header).num_additional = 0;
        
        /* make_response_bytes_for_ip */
        hexDump("send data", buf, n);
        
        n = sendto(sockfd, buf, n, 0, (struct sockaddr *) &clientaddr, clientlen);
        if (n < 0) printf("Failed to reply.\n");
        
        nextOne:
        free(temp);
        temp = NULL;
    }
}
