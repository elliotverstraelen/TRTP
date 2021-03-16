#include "packet_interface.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct __attribute__((__packed__)) pkt {
   ptypes_t type : 2;
   uint8_t tr : 1;
   uint8_t window : 5;
   uint16_t length : 16;
   uint32_t timestamp : 32;
   uint32_t crc1 : 32; //checksum for send
   char *pkt_get_payload;
   uint32_t crc2 : 32;

};

pkt_t* pkt_new()
{
    pkt_t *new = malloc(sizeof(pkt_t));
    if(new == NULL){
        return NULL;
    }
    return new;
}

void pkt_del(pkt_t *pkt)
{
    if(pkt_get_payload(pkt)!=NULL){
        free(pkt->payload);
    }
    free(pkt);
    pkt = NULL;
    
}

pkt_status_code pkt_decode(const char *data, const size_t len, pkt_t *pkt)
{
    if(len==0 || len<11){
        return E_UNCONSISTENT;
    }
    if(len<7){
        return E_NOHEADER;
    }

    /** FIRST BYTES **/
    uint8_t firstByte;
    memcpy(&firstByte, data, 1);

    /** TYPE **/
    ptypes_t type = firstByte >> 6 //right shift
    if(type!=1 && type!=2 && type!=3){
        return E_TYPE;
    }
    else{
        pkt_set_type(pkt, type);
    }

    /** TR **/
    uint8_t tr = firstByte & 0b00111111;
    tr = tr >> 5;
    pkt_status_code tr_sc = pkt_set_tr(pkt, tr)
    if()
}

pkt_status_code pkt_encode(const pkt_t* pkt, char *buf, size_t *len)
{
    /* Your code will be inserted here */
}

ptypes_t pkt_get_type  (const pkt_t* pkt)
{
    /* Your code will be inserted here */
}

uint8_t  pkt_get_tr(const pkt_t* pkt)
{
    /* Your code will be inserted here */
}

uint8_t  pkt_get_window(const pkt_t* pkt)
{
    /* Your code will be inserted here */
}

uint8_t  pkt_get_seqnum(const pkt_t* pkt)
{
    /* Your code will be inserted here */
}

uint16_t pkt_get_length(const pkt_t* pkt)
{
    /* Your code will be inserted here */
}

uint32_t pkt_get_timestamp   (const pkt_t* pkt)
{
    /* Your code will be inserted here */
}

uint32_t pkt_get_crc1   (const pkt_t* pkt)
{
    /* Your code will be inserted here */
}

uint32_t pkt_get_crc2   (const pkt_t* pkt)
{
    /* Your code will be inserted here */
}

const char* pkt_get_payload(const pkt_t* pkt)
{
    /* Your code will be inserted here */
}


pkt_status_code pkt_set_type(pkt_t *pkt, const ptypes_t type)
{
    /* Your code will be inserted here */
}

pkt_status_code pkt_set_tr(pkt_t *pkt, const uint8_t tr)
{
    /* Your code will be inserted here */
}

pkt_status_code pkt_set_window(pkt_t *pkt, const uint8_t window)
{
    /* Your code will be inserted here */
}

pkt_status_code pkt_set_seqnum(pkt_t *pkt, const uint8_t seqnum)
{
    /* Your code will be inserted here */
}

pkt_status_code pkt_set_length(pkt_t *pkt, const uint16_t length)
{
    /* Your code will be inserted here */
}

pkt_status_code pkt_set_timestamp(pkt_t *pkt, const uint32_t timestamp)
{
    /* Your code will be inserted here */
}

pkt_status_code pkt_set_crc1(pkt_t *pkt, const uint32_t crc1)
{
    /* Your code will be inserted here */
}

pkt_status_code pkt_set_crc2(pkt_t *pkt, const uint32_t crc2)
{
    /* Your code will be inserted here */
}

pkt_status_code pkt_set_payload(pkt_t *pkt,
                                const char *data,
                                const uint16_t length)
{
    /* Your code will be inserted here */
}

ssize_t predict_header_length(const pkt_t *pkt)
{
    /* Your code will be inserted here */
}