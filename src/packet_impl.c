#include "packet_interface.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
struct __attribute__((__packed__)) pkt {
   //1st byte
   ptypes_t type : 2;
   uint8_t tr : 1;
   uint8_t window : 5;

   //2nd & 3rd byte
   uint16_t length : 16;
   uint8_t seqnum : 8;
   uint32_t timestamp : 32;
   uint32_t crc1 : 32; //checksum for send
   char *payload; //using pointer for performance issues
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
    if(pkt!=NULL){
        if(pkt_get_payload(pkt)!=NULL){
            free(pkt->payload);
            pkt->payload = NULL;
        }
        free(pkt);
        pkt = NULL;
    }
}

pkt_status_code pkt_decode(const char *data, const size_t len, pkt_t *pkt)
{
    memcpy(pkt, data, sizeof(uint8_t));
    //Window, tr and type
    if((pkt_get_type(pkt) != PTYPE_DATA)&&(pkt_get_type(pkt) != PTYPE_ACK)&&(pkt_get_type(pkt) != PTYPE_NACK)){
		return E_TYPE;
	}

    // seqnum
	uint8_t seqnum;
	memcpy(&seqnum, data+1,sizeof(uint8_t));
	pkt_set_seqnum(pkt, seqnum);

	// length
	uint16_t length;
	memcpy(&length, data+2,sizeof(uint16_t));
	length = ntohs(length);
	pkt_set_length(pkt, length);

    if((length != len-4*sizeof(uint32_t))&&(length != len-3*sizeof(uint32_t))){
		return E_LENGTH;
	}

	if((pkt->tr == 1)&&(length!=0)){
		return E_TR;
	}
	// timestamp
	uint32_t timestamp;
	memcpy(&timestamp, data+4,sizeof(uint32_t));
	pkt_set_timestamp(pkt, timestamp);

	// crc1
	uint32_t crc1;
	memcpy(&crc1, data+8, sizeof(uint32_t));
    crc1 = ntohl(crc1);
	pkt_set_crc1(pkt, crc1);

	// verif crc1
	uint32_t testCrc1 = 0;
	char dataNonTr[8];
	memcpy(dataNonTr, data, sizeof(uint64_t));
	dataNonTr[0] = dataNonTr[0] & 0b11011111;
	testCrc1 = crc32(testCrc1, (Bytef *)(&dataNonTr), sizeof(uint64_t));
    if(testCrc1 != crc1){
		return E_CRC;
	}
	// payload
	pkt_set_payload(pkt, data+12, length);

    if(length*sizeof(char) == len-4*sizeof(uint32_t)){
		// crc2
		uint32_t crc2;
		memcpy(&crc2, data+12+length, sizeof(uint32_t));
        crc2 = ntohl(crc2);
		pkt_set_crc2(pkt, crc2);

		// verif crc2
		uint32_t testCrc2 = 0;
		testCrc2 = crc32(testCrc2, (Bytef *)(data +12), length);

		if(testCrc2 != crc2){
			return E_CRC;
		}
	}
    else{
        pkt_set_crc2(pkt, 0);
    }
    return PKT_OK;
}

pkt_status_code pkt_encode(const pkt_t* pkt, char *buf, size_t *len)
{
    int header_length = (int) predict_header_length(pkt);
    int total_length = header_length + pkt_get_length(pkt) + 4;

    if(pkt_get_tr(pkt) == 0 && pkt_get_length(pkt)!=0){
        total_length += 4;
    }
    if(total_length >(int) *len){
        return E_NOMEM;
    }
    if(pkt_get_type(pkt)!=PTYPE_DATA && pkt_get_tr(pkt)!=0){
        return E_TR;
    }
    //window, tr and type
    memcpy(buf, pkt, sizeof(uint8_t));
    *len = sizeof(uint8_t);
    //seqnum
    uint8_t seqnum = pkt_get_seqnum(pkt);
    memcpy(buf+1, &seqnum, sizeof(uint8_t));
    *len += sizeof(uint8_t);
    //length
    uint16_t length = pkt_get_length(pkt);
    uint16_t nlength = htons(length);
    memcpy(buf+2, &nlength, sizeof(uint16_t));
    *len += sizeof(uint16_t);
	// timestamp
	uint32_t timestamp = pkt_get_timestamp(pkt);
	memcpy(buf+4, &timestamp,sizeof(uint32_t));
	*len += sizeof(uint32_t);
    // verif crc1
	uint32_t testCrc1 = 0;
	char dataNonTr[8];
	memcpy(dataNonTr, buf, sizeof(uint64_t));
	dataNonTr[0] = dataNonTr[0] & 0b11011111;
	testCrc1 = crc32(testCrc1, (Bytef *)(&dataNonTr), sizeof(uint64_t));
    // crc1
    uint32_t crc1 = htonl(testCrc1);
	memcpy(buf+8, &crc1,sizeof(uint32_t));
	*len += sizeof(uint32_t);
    // payload
	memcpy(buf+12, pkt_get_payload(pkt), length);
	*len += length;
    // crc2
    if(pkt_get_payload(pkt)!=0){
        // verif crc2
		uint32_t testCrc2 = 0;
		testCrc2 = crc32(testCrc2, (Bytef *)(buf +12), length);

        uint32_t crc2 = testCrc2;
		crc2 = htonl(crc2);

		memcpy(buf+12+length, &crc2, sizeof(uint32_t));
        *len += sizeof(uint32_t);
	}
    return PKT_OK;
}

ptypes_t pkt_get_type  (const pkt_t* pkt)
{
    if(pkt!=NULL){
        pkt->type;
    }
}

uint8_t  pkt_get_tr(const pkt_t* pkt)
{
    if(pkt!=NULL){
        return pkt->tr;
    }
}

uint8_t  pkt_get_window(const pkt_t* pkt)
{
    if(pkt!=NULL){
        return pkt->window;
    }
}

uint8_t  pkt_get_seqnum(const pkt_t* pkt)
{
    if(pkt!=NULL){
        pkt->seqnum;
    }
}

uint16_t pkt_get_length(const pkt_t* pkt)
{
    if(pkt!=NULL){
        return pkt->length;
    }
}

uint32_t pkt_get_timestamp(const pkt_t* pkt)
{
    if(pkt!=NULL){
        return pkt->timestamp;
    }
}

uint32_t pkt_get_crc1   (const pkt_t* pkt)
{
    if(pkt!=NULL){
        return pkt->crc1;
    }
}

uint32_t pkt_get_crc2   (const pkt_t* pkt)
{
    if(pkt!=NULL){
        return pkt->crc2;
    }
}

const char* pkt_get_payload(const pkt_t* pkt)
{
    if(pkt!=NULL){
        pkt->payload;
    }
}


pkt_status_code pkt_set_type(pkt_t *pkt, const ptypes_t type)
{
    if(type != PTYPE_ACK && type != PTYPE_NACK && type != PTYPE_DATA){
        return E_TYPE;
    }
    pkt->type = type;
    return PKT_OK;
}

pkt_status_code pkt_set_tr(pkt_t *pkt, const uint8_t tr)
{
    pkt->tr = tr;
    return PKT_OK;
}

pkt_status_code pkt_set_window(pkt_t *pkt, const uint8_t window)
{
   if(window > MAX_WINDOW_SIZE){
       return E_WINDOW;
   }
   pkt->window = window;
   return PKT_OK;
}

pkt_status_code pkt_set_seqnum(pkt_t *pkt, const uint8_t seqnum)
{
    pkt->seqnum = seqnum;
    return PKT_OK;
}

pkt_status_code pkt_set_length(pkt_t *pkt, const uint16_t length)
{
    if (length > MAX_PAYLOAD_SIZE){
        return E_LENGTH;
    }
    pkt->length = length;
    return PKT_OK;
}

pkt_status_code pkt_set_timestamp(pkt_t *pkt, const uint32_t timestamp)
{
    pkt->timestamp = timestamp;
    return PKT_OK;
}

pkt_status_code pkt_set_crc1(pkt_t *pkt, const uint32_t crc1)
{
    pkt->crc1 = crc1;
    return PKT_OK;
}

pkt_status_code pkt_set_crc2(pkt_t *pkt, const uint32_t crc2)
{
    pkt->crc2 = crc2;
    return PKT_OK;
}

pkt_status_code pkt_set_payload(pkt_t *pkt,
                                const char *data,
                                const uint16_t length)
{
    if(pkt == NULL){ return E_UNCONSISTENT;}
    if(length>MAX_PAYLOAD_SIZE){
        return E_NOMEM;
    }
    pkt_status_code length_status2 = pkt_set_length(pkt, length);
    if(length_status2!=PKT_OK){
        return length_status2;
    }
    if(pkt->payload != NULL){
        free(pkt->payload);
        return E_NOMEM;
    }
    memcpy(pkt->payload, data, length);
    return 
    PKT_OK;
}

//CREATE A PACKET WITH SPECIFICATIONS FOR FIELDS
char *pkt_create(const uint8_t type, const uint8_t window, const uint8_t seqnum, const uint32_t timestamp){
    pkt_t* newpkt = pkt_new();
	if(newpkt==NULL){
		perror("error new pkt");
		return NULL;
	}
	pkt_set_type(newpkt, type);
	pkt_set_tr(newpkt, 0);
	pkt_set_window(newpkt, window);
	pkt_set_seqnum(newpkt, seqnum);
	pkt_set_length(newpkt, 0);
	pkt_set_timestamp(newpkt, timestamp);

    char *buf = malloc(12 * sizeof(char));

    memcpy(buf, newpkt, sizeof(uint8_t));

	memcpy(buf+1, &seqnum,sizeof(uint8_t));

	uint16_t length = 0b0000000000000000;
	uint16_t nlength = htons(length);
	memcpy(buf+2, &nlength,sizeof(uint16_t));

	memcpy(buf+4, &timestamp,sizeof(uint32_t));

	uint32_t testCrc1 = 0;
	char dataNonTr[8];
	memcpy(dataNonTr, buf, sizeof(uint64_t));
	dataNonTr[0] = dataNonTr[0] & 0b11011111;
	testCrc1 = crc32(testCrc1, (Bytef *)(&dataNonTr), sizeof(uint64_t));

	uint32_t crc1 = htonl(testCrc1);
	memcpy(buf+8, &crc1,sizeof(uint32_t));
	
	pkt_del(newpkt);
	return buf;
}

pkt_t* pkt_create_sender(const uint8_t window, const uint8_t seqnum, const uint16_t len, const uint32_t timestamp, const char *payload){
	pkt_t* newpkt = pkt_new();
	if(newpkt==NULL){
		perror("error for creation of new pkt");
		return NULL;
	}
	pkt_set_type(newpkt, PTYPE_DATA);
	pkt_set_tr(newpkt, 0);
	pkt_set_window(newpkt, window);
	pkt_set_seqnum(newpkt, seqnum);
	pkt_set_length(newpkt, len);
	pkt_set_timestamp(newpkt, timestamp);
	pkt_set_payload(newpkt, payload, len);
	return newpkt;
}

ssize_t predict_header_length(const pkt_t *pkt)
{
    if(pkt_get_length(pkt) >= 0x8000){return -1;}
    if(pkt_get_length(pkt) > 128){return 8;}
    else{return 7;}
}