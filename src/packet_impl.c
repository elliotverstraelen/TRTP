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
   char *payload;
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
    ptypes_t type = firstByte >> 6; //right shift
    if(type!=1 && type!=2 && type!=3){
        return E_TYPE;
    }
    else{
        pkt_set_type(pkt, type);
    }

    /** TR **/
    uint8_t tr = firstByte & 0b00111111;
    tr = tr >> 5;
    pkt_status_code tr_status = pkt_set_tr(pkt, tr);
    if(tr_status != PKT_OK){
        return tr_status;
    }
    /** WINDOW **/

    pkt_status_code window_status = pkt_set_window(pkt, firstByte & 0b00011111);
    if(windows_status != PKT_OK){
        return windows_status;
    }

    /** LENGTH **/
    if(pkt_get_type(pkt) == PTYPE_DATA){
        uint16_t length;
        memcpy(&length, &data[1], 2);
        length = htohs(length);
        pkt_status_code length_status = pkt_set_length(pkt, length);
        if(length_status != PKT_OK){
            return length_status;
        }
    }

    /** SEQNUM **/

    int offset = 0; //THIS IS USED TO GET THE LOCATION OF THE BITS IN THE PACKET STRUCTURE

    uint8_t seq;
    memcpy(&seq, &data[1 + offset], 1);
    pkt_status_code seqnum_status = pkt_set_seqnum(pkt, seq);
    if(seqnum_status != PKT_OK){
        return seqnum_status;
    }
    
    /** TIMESTAMP **/
    uint32_t ts;
    memcpy(&ts, &data[2 + offset], 4);
    pkt_status_code ts_status = pkt_set_timestamp(pkt, ts);
    if(ts_status != PKT_OK){
        return ts_status;
    }

    /** CRC1 **/
    uint32_t crc1;
    memcpy(&crc1, &data[6 + offset], 4);
    crc1 = ntohl(crc1); //Reverse order of the bits
    //TODO

    /** PAYLOAD **/
    int payload_length = pkt_get_length(pkt);
    char *payload = (char *) malloc(sizeof(char)*payload_length);
    memcpy(payload, data[10 + offset], payload_length);
    pkt_status_code payload_status = pkt_set_payload(pkt, payload, payload_length);
    free(payload);
    if(payload_status != PKT_OK){
        return payload_status;
    }

    /** CRC32 HEADER VERIF **/
    //uint32_t crc1 = crc32()
    //TODO

    /** CRC32 PAYLOAD VERIF**/
    uint32_t crc32;
    memcpy(&crc32, &data[10 + offset + pkt->length], 4);
    crc32 = htohl(crc32); //INVERSE BITS

    //TODO

    


}
return PKT_OK;

pkt_status_code pkt_encode(const pkt_t* pkt, char *buf, size_t *len)
{
    //TODO
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