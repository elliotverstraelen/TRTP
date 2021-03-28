#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>

#include "log.h"
#include <stdbool.h>

#define BUFF_LEN 
#define MAX_SEQNUM 256

int print_usage(char *prog_name) {
    ERROR("Usage:\n\t%s [-f filename] [-s stats_filename] receiver_ip receiver_port", prog_name);
    return EXIT_FAILURE;
}

// gcc sender.c -o sender
// ./sender ipv6 port
int main(int argc, char **argv) {
    int opt;

    char *filename = NULL;
    char *stats_filename = NULL;
    char *receiver_ip = NULL;
    char *receiver_port_err;
    uint16_t receiver_port;
    bool binaryfile=0;

    uint8_t lastseqnum = 0; //seqnum of last packet read
    uint8_t window = 1; //size of window
    uint8_t firstseqnumwindow = 0;
    uint8_t lastackseqnum = -1; //Seqnum of the last ack received

    //Let's store the already encoded packets in a char *
    struct dataqueue {
        char *bufpkt;
	    uint8_t seqnum;
	    uint16_t len;
	    struct timespec time;
	    struct dataqueue *next;
    };

    //Start of the queue with pkts that the receiver has not received yet
    struct dataqueue *startofqueue = NULL;

    //Next pkt to send
    struct dataqueue *firsttosend = NULL;

    //End of the queue with pkts to send
    struct dataqueue *lasttosend = NULL;

    //Pkts not sent yet (for the 1st time)
    int pkt_to_send = 0;

    //Pkts not received by the receiver yet
    int pkt_waiting = 0;

        

    while ((opt = getopt(argc, argv, "f:s:h")) != -1) {
        switch (opt) {
        case 'f':
            filename = optarg;
            break;
        case 'h':
            return print_usage(argv[0]);
        case 's':
            stats_filename = optarg;
            break;
        default:
            return print_usage(argv[0]);
        }
    }

    if (optind + 2 != argc) {
        ERROR("Unexpected number of positional arguments");
        return print_usage(argv[0]);
    }

    receiver_ip = argv[optind];
    receiver_port = (uint16_t) strtol(argv[optind + 1], &receiver_port_err, 10);
    if (*receiver_port_err != '\0') {
        ERROR("Receiver port parameter is not a number");
        return print_usage(argv[0]);
    }

    ASSERT(1 == 1); // Try to change it to see what happens when it fails
    DEBUG_DUMP("Some bytes", 11); // You can use it with any pointer type

    // This is not an error per-se.
    ERROR("Sender has following arguments: filename is %s, stats_filename is %s, receiver_ip is %s, receiver_port is %u",
        filename, stats_filename, receiver_ip, receiver_port);

    DEBUG("You can only see me if %s", "you built me using `make debug`");
    ERROR("This is not an error, %s", "now let's code!");
    // Now let's code!



    int remove_pkt(uint8_T seqnum){
        //TODO
    }

    //get the number of the next ptype_ack packet
    int succ(int seqnum){
        return (seqnum +1) % 256;
    }
    //checks if the seqnum is in the window
    int is_in_window(int seqnum){
        //TODO
    }

    //SENDS firstosend PACKET in the Queue if it's seqnum is in the window
    int send_pkt(const int sfd){
        //TODO
    }
    int add_pkt_to_queue( char* buf, int len){
        //TODO
    }
    //Send the disconnection request to receiver
    int disconnect(int sfd){
        //TODO
    }
    //SEND data from input
    int send_data(const int sfd, const int fd){
        //TODO
    }


    int sock = socket(AF_INET6, SOCK_DGRAM, 0);

    // REGISTER 
    struct sockaddr_in6 receiver_addr;
    memset(&receiver_addr, 0, sizeof(struct sockaddr_in6));
    receiver_addr.sin6_family = AF_INET6;
    receiver_addr.sin6_port = htons(receiver_port);
    inet_pton(AF_INET6, receiver_ip, &receiver_addr.sin6_addr);
    connect(sock, (const struct sockaddr *) &receiver_addr, sizeof(receiver_addr));

    //OPENING THE FILEDESCRIPTOR
    int fp;
    if(filename){
        if(binaryfile){
            if((fp = fileno(fopen(filename, "rb"))) == -1){
                fprintf(stderr, "Open of file failed!\n");
                close(fp);
            }
        }
        else if((fp = open(filename,O_RDONLY)) ==-1){
            fprintf(stderr, "Open of file failed!\n");
        }
    }
    else{
        fp = STDIN_FILENO;
    }

    int finished = 0;
    int eof = 0;
    int win = 32;



    //send firsttosend pkt in the queue
    int send_pkt(const int sfd){
        //TODO
    }
    
    return EXIT_SUCCESS;
}
