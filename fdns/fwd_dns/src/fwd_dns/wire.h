
#ifndef _LDNS_WIRE_H_
#define _LDNS_WIRE_H_

#include <stdint.h>
#include <assert.h>

#include "common.h"
#include "utils.h"

#define NOERROR 0
#define FORMAT_ERROR 1
#define SERVER_FAIL 2
#define NXDOMAIN 3
#define NOT_IMPLEMENT 4
#define REFUSED 5


/*! \brief Offset of DNS header fields in wireformat. */
enum ldns_wire_offsets {
	LDNS_WIRE_OFFSET_ID = 0,
	LDNS_WIRE_OFFSET_FLAGS1 = 2,
	LDNS_WIRE_OFFSET_FLAGS2 = 3,
	LDNS_WIRE_OFFSET_QDCOUNT = 4,
	LDNS_WIRE_OFFSET_ANCOUNT = 6,
	LDNS_WIRE_OFFSET_NSCOUNT = 8,
	LDNS_WIRE_OFFSET_ARCOUNT = 10
};

/*! \brief Minimum size for some parts of the DNS packet. */
enum ldns_wire_sizes {
	LDNS_WIRE_HEADER_SIZE = 12,
	LDNS_WIRE_QUESTION_MIN_SIZE = 5,
	LDNS_WIRE_RR_MIN_SIZE = 11
};

/*
 * Packet header manipulation functions.
 */
static inline uint16_t ldns_wire_get_id(const uint8_t *packet)
{
    return adns_wire_read_u16(packet + LDNS_WIRE_OFFSET_ID);
}

static inline void ldns_wire_set_id(uint8_t *packet, uint16_t id)
{
    adns_wire_write_u16(packet + LDNS_WIRE_OFFSET_ID, id);
}

static inline uint8_t ldns_wire_get_flags1(const uint8_t *packet)
{
    return *(packet + LDNS_WIRE_OFFSET_FLAGS1);
}

static inline uint8_t ldns_wire_set_flags1(uint8_t *packet, uint8_t flags1)
{
    return *(packet + LDNS_WIRE_OFFSET_FLAGS1) = flags1;
}

static inline uint8_t ldns_wire_get_flags2(const uint8_t *packet)
{
    return *(packet + LDNS_WIRE_OFFSET_FLAGS2);
}

static inline uint8_t ldns_wire_set_flags2(uint8_t *packet, uint8_t flags2)
{
    return *(packet + LDNS_WIRE_OFFSET_FLAGS2) = flags2;
}

static inline uint16_t ldns_wire_get_qdcount(const uint8_t *packet)
{
    return adns_wire_read_u16(packet + LDNS_WIRE_OFFSET_QDCOUNT);
}

static inline void ldns_wire_set_qdcount(uint8_t *packet, uint16_t qdcount)
{
    adns_wire_write_u16(packet + LDNS_WIRE_OFFSET_QDCOUNT, qdcount);
}

static inline void ldns_wire_add_qdcount(uint8_t *packet, int16_t n)
{
    adns_wire_write_u16(packet + LDNS_WIRE_OFFSET_QDCOUNT,
                        ldns_wire_get_qdcount(packet) + n);
}

static inline uint16_t ldns_wire_get_ancount(const uint8_t *packet)
{
    return adns_wire_read_u16(packet + LDNS_WIRE_OFFSET_ANCOUNT);
}

static inline void ldns_wire_set_ancount(uint8_t *packet, uint16_t ancount)
{
    adns_wire_write_u16(packet + LDNS_WIRE_OFFSET_ANCOUNT, ancount);
}

static inline void ldns_wire_add_ancount(uint8_t *packet, int16_t n)
{
    adns_wire_write_u16(packet + LDNS_WIRE_OFFSET_ANCOUNT,
                        ldns_wire_get_ancount(packet) + n);
}

static inline uint16_t ldns_wire_get_nscount(const uint8_t *packet)
{
    return adns_wire_read_u16(packet + LDNS_WIRE_OFFSET_NSCOUNT);
}

static inline void ldns_wire_set_nscount(uint8_t *packet, uint16_t nscount)
{
    adns_wire_write_u16(packet + LDNS_WIRE_OFFSET_NSCOUNT, nscount);
}

static inline void ldns_wire_add_nscount(uint8_t *packet, int16_t n)
{
    adns_wire_write_u16(packet + LDNS_WIRE_OFFSET_NSCOUNT,
                        ldns_wire_get_nscount(packet) + n);
}

static inline uint16_t ldns_wire_get_arcount(const uint8_t *packet)
{
    return adns_wire_read_u16(packet + LDNS_WIRE_OFFSET_ARCOUNT);
}

static inline void ldns_wire_set_arcount(uint8_t *packet, uint16_t arcount)
{
    adns_wire_write_u16(packet + LDNS_WIRE_OFFSET_ARCOUNT, arcount);
}

static inline void ldns_wire_add_arcount(uint8_t *packet, int16_t n)
{
    adns_wire_write_u16(packet + LDNS_WIRE_OFFSET_ARCOUNT,
                        ldns_wire_get_arcount(packet) + n);
}

/*
 * Packet header flags manipulation functions.
 */
enum ldns_wire_flags1_consts {
	LDNS_WIRE_RD_MASK = (uint8_t)0x01U,      /*!< RD bit mask. */
	LDNS_WIRE_RD_SHIFT = 0,                  /*!< RD bit shift. */
	LDNS_WIRE_TC_MASK = (uint8_t)0x02U,      /*!< TC bit mask. */
	LDNS_WIRE_TC_SHIFT = 1,                  /*!< TC bit shift. */
	LDNS_WIRE_AA_MASK = (uint8_t)0x04U,      /*!< AA bit mask. */
	LDNS_WIRE_AA_SHIFT = 2,                  /*!< AA bit shift. */
	LDNS_WIRE_OPCODE_MASK = (uint8_t)0x78U,  /*!< OPCODE mask. */
	LDNS_WIRE_OPCODE_SHIFT = 3,              /*!< OPCODE shift. */
	LDNS_WIRE_QR_MASK = (uint8_t)0x80U,      /*!< QR bit mask. */
	LDNS_WIRE_QR_SHIFT = 7                   /*!< QR bit shift. */
};

/*! \brief Constants for DNS header flags in the second flags byte. */
enum ldns_wire_flags2_consts {
	LDNS_WIRE_RCODE_MASK = (uint8_t)0x0fU,  /*!< RCODE mask. */
	LDNS_WIRE_RCODE_SHIFT = 0,              /*!< RCODE shift. */
	LDNS_WIRE_CD_MASK = (uint8_t)0x10U,     /*!< CD bit mask. */
	LDNS_WIRE_CD_SHIFT = 4,                 /*!< CD bit shift. */
	LDNS_WIRE_AD_MASK = (uint8_t)0x20U,     /*!< AD bit mask. */
	LDNS_WIRE_AD_SHIFT = 5,                 /*!< AD bit shift. */
	LDNS_WIRE_Z_MASK = (uint8_t)0x40U,      /*!< Zero bit mask. */
	LDNS_WIRE_Z_SHIFT = 6,                  /*!< Zero bit shift. */
	LDNS_WIRE_RA_MASK = (uint8_t)0x80U,     /*!< RA bit mask. */
	LDNS_WIRE_RA_SHIFT = 7                  /*!< RA bit shift. */
};

/*
 * Functions for getting / setting / clearing flags and codes directly in packet
 */
static inline uint16_t ldns_wire_get_u16(const uint8_t *packet,uint8_t offset)
{
	const uint16_t *p = (const uint16_t *)(packet + offset);
	return Lntohs(*p);
}

static inline void ldns_wire_set_u16(uint8_t *packet,uint8_t offset,uint16_t x)
{
	uint16_t *p = (uint16_t *)(packet + offset);
	*p = Lhtons(x);
}

static inline uint8_t ldns_wire_get_u8(const uint8_t *packet,uint8_t offset)
{
	return *(packet + offset);
}

static inline void ldns_wire_set_u8(uint8_t *packet,uint8_t offset,uint8_t x)
{
	*(packet + offset) = x;
}

static inline uint8_t ldns_wire_get_rd(const uint8_t *packet)
{
	return *(packet + LDNS_WIRE_OFFSET_FLAGS1) & LDNS_WIRE_RD_MASK;
}

static inline void ldns_wire_set_rd(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS1) |= LDNS_WIRE_RD_MASK;
}

static inline void ldns_wire_clear_rd(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS1) &= ~LDNS_WIRE_RD_MASK;
}

static inline uint8_t ldns_wire_get_tc(const uint8_t *packet)
{
	return *(packet + LDNS_WIRE_OFFSET_FLAGS1) & LDNS_WIRE_TC_MASK;
}

static inline void ldns_wire_set_tc(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS1) |= LDNS_WIRE_TC_MASK;
}

static inline void ldns_wire_clear_tc(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS1) &= ~LDNS_WIRE_TC_MASK;
}

static inline uint8_t ldns_wire_get_aa(const uint8_t *packet)
{
	return *(packet + LDNS_WIRE_OFFSET_FLAGS1) & LDNS_WIRE_AA_MASK;
}

static inline void ldns_wire_set_aa(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS1) |= LDNS_WIRE_AA_MASK;
}

static inline void ldns_wire_clear_aa(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS1) &= ~LDNS_WIRE_AA_MASK;
}

static inline uint8_t ldns_wire_get_opcode(const uint8_t *packet)
{
	return (*(packet + LDNS_WIRE_OFFSET_FLAGS1)
	        & LDNS_WIRE_OPCODE_MASK) >> LDNS_WIRE_OPCODE_SHIFT;
}

static inline void ldns_wire_set_opcode(uint8_t *packet, short opcode)
{
	uint8_t *flags1 = packet + LDNS_WIRE_OFFSET_FLAGS1;
	*flags1 = (*flags1 & ~LDNS_WIRE_OPCODE_MASK)
	          | ((opcode) << LDNS_WIRE_OPCODE_SHIFT);
}

static inline uint8_t ldns_wire_get_qr(const uint8_t *packet)
{
	return *(packet + LDNS_WIRE_OFFSET_FLAGS1) & LDNS_WIRE_QR_MASK;
}

static inline void ldns_wire_set_qr(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS1) |= LDNS_WIRE_QR_MASK;
}

static inline void ldns_wire_clear_qr(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS1) &= ~LDNS_WIRE_QR_MASK;
}

static inline uint8_t ldns_wire_get_rcode(const uint8_t *packet)
{
	return *(packet + LDNS_WIRE_OFFSET_FLAGS2)
	       & LDNS_WIRE_RCODE_MASK;
}

static inline void ldns_wire_set_rcode(uint8_t *packet, short rcode)
{
	uint8_t *flags2 = packet + LDNS_WIRE_OFFSET_FLAGS2;
	*flags2 = (*flags2 & ~LDNS_WIRE_RCODE_MASK) | (rcode);
}

static inline uint8_t ldns_wire_get_cd(const uint8_t *packet)
{
	return *(packet + LDNS_WIRE_OFFSET_FLAGS2) & LDNS_WIRE_CD_MASK;
}

static inline void ldns_wire_set_cd(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS2) |= LDNS_WIRE_CD_MASK;
}

static inline void ldns_wire_clear_cd(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS2) &= ~LDNS_WIRE_CD_MASK;
}

static inline uint8_t ldns_wire_get_ad(const uint8_t *packet)
{
	return *(packet + LDNS_WIRE_OFFSET_FLAGS2) & LDNS_WIRE_AD_MASK;
}

static inline void ldns_wire_set_ad(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS2) |= LDNS_WIRE_AD_MASK;
}

static inline void ldns_wire_clear_ad(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS2) &= ~LDNS_WIRE_AD_MASK;
}

static inline uint8_t ldns_wire_get_z(const uint8_t *packet)
{
	return *(packet + LDNS_WIRE_OFFSET_FLAGS2) & LDNS_WIRE_Z_MASK;
}

static inline void ldns_wire_set_z(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS2) |= LDNS_WIRE_Z_MASK;
}

static inline void ldns_wire_clear_z(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS2) &= ~LDNS_WIRE_Z_MASK;
}

static inline uint8_t ldns_wire_get_ra(const uint8_t *packet)
{
	return *(packet + LDNS_WIRE_OFFSET_FLAGS2) & LDNS_WIRE_RA_MASK;
}

static inline void ldns_wire_set_ra(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS2) |= LDNS_WIRE_RA_MASK;
}

static inline void ldns_wire_clear_ra(uint8_t *packet)
{
	*(packet + LDNS_WIRE_OFFSET_FLAGS2) &= ~LDNS_WIRE_RA_MASK;
}

/*
 * Functions for getting / setting / clearing flags in flags variable
 */
static inline uint8_t ldns_wire_flags_get_rd(uint8_t flags1)
{
	return flags1 & LDNS_WIRE_RD_MASK;
}

static inline void ldns_wire_flags_set_rd(uint8_t *flags1)
{
	*flags1 |= LDNS_WIRE_RD_MASK;
}

static inline void ldns_wire_flags_clear_rd(uint8_t *flags1)
{
	*flags1 &= ~LDNS_WIRE_RD_MASK;
}

static inline uint8_t ldns_wire_flags_get_tc(uint8_t flags1)
{
	return flags1 & LDNS_WIRE_TC_MASK;
}

static inline void ldns_wire_flags_set_tc(uint8_t *flags1)
{
	*flags1 |= LDNS_WIRE_TC_MASK;
}

static inline void ldns_wire_flags_clear_tc(uint8_t *flags1)
{
	*flags1 &= ~LDNS_WIRE_TC_MASK;
}

static inline uint8_t ldns_wire_flags_get_aa(uint8_t flags1)
{
	return flags1 & LDNS_WIRE_AA_MASK;
}

static inline void ldns_wire_flags_set_aa(uint8_t *flags1)
{
	*flags1 |= LDNS_WIRE_AA_MASK;
}

static inline void ldns_wire_flags_clear_aa(uint8_t *flags1)
{
	*flags1 &= ~LDNS_WIRE_AA_MASK;
}

static inline uint8_t ldns_wire_flags_get_opcode(uint8_t flags1)
{
	return (flags1 & LDNS_WIRE_OPCODE_MASK)
	        >> LDNS_WIRE_OPCODE_SHIFT;
}

static inline void ldns_wire_flags_set_opcode(uint8_t *flags1, short opcode)
{
	*flags1 = (*flags1 & ~LDNS_WIRE_OPCODE_MASK)
	          | ((opcode) << LDNS_WIRE_OPCODE_SHIFT);
}

static inline uint8_t ldns_wire_flags_get_qr(uint8_t flags1)
{
	return flags1 & LDNS_WIRE_QR_MASK;
}

static inline void ldns_wire_flags_set_qr(uint8_t *flags1)
{
	*flags1 |= LDNS_WIRE_QR_MASK;
}

static inline void ldns_wire_flags_clear_qr(uint8_t *flags1)
{
	*flags1 &= ~LDNS_WIRE_QR_MASK;
}

static inline uint8_t ldns_wire_flags_get_rcode(uint8_t flags2)
{
	return flags2 & LDNS_WIRE_RCODE_MASK;
}

static inline void ldns_wire_flags_set_rcode(uint8_t *flags2, short rcode)
{
	*flags2 = (*flags2 & ~LDNS_WIRE_RCODE_MASK) | (rcode);
}

static inline uint8_t ldns_wire_flags_get_cd(uint8_t flags2)
{
	return flags2 & LDNS_WIRE_CD_MASK;
}

static inline void ldns_wire_flags_set_cd(uint8_t *flags2)
{
	*flags2 |= LDNS_WIRE_CD_MASK;
}

static inline void ldns_wire_flags_clear_cd(uint8_t *flags2)
{
	*flags2 &= ~LDNS_WIRE_CD_MASK;
}

static inline uint8_t ldns_wire_flags_get_ad(uint8_t flags2)
{
	return flags2 & LDNS_WIRE_AD_MASK;
}

static inline void ldns_wire_flags_set_ad(uint8_t *flags2)
{
	*flags2 |= LDNS_WIRE_AD_MASK;
}

static inline void ldns_wire_flags_clear_ad(uint8_t *flags2)
{
	*flags2 &= ~LDNS_WIRE_AD_MASK;
}

static inline uint8_t ldns_wire_flags_get_z(uint8_t flags2)
{
	return flags2 & LDNS_WIRE_Z_MASK;
}

static inline void ldns_wire_flags_set_z(uint8_t *flags2)
{
	*flags2 |= LDNS_WIRE_Z_MASK;
}

static inline void ldns_wire_flags_clear_z(uint8_t *flags2)
{
	*flags2 &= ~LDNS_WIRE_Z_MASK;
}

static inline uint8_t ldns_wire_flags_get_ra(uint8_t flags2)
{
	return flags2 & LDNS_WIRE_RA_MASK;
}

static inline void ldns_wire_flags_set_ra(uint8_t *flags2)
{
	*flags2 |= LDNS_WIRE_RA_MASK;
}

static inline void ldns_wire_flags_clear_ra(uint8_t *flags2)
{
	*flags2 &= ~LDNS_WIRE_RA_MASK;
}

/*
 * Pointer manipulation
 */
enum adns_wire_pointer_consts {
    ADNS_WIRE_PTR = (uint8_t) 0xC0,
    ADNS_WIRE_PTR_BASE = (uint16_t) 0xC000,
    ADNS_WIRE_PTR_MAX = (uint16_t) 0x3FFF
};

static inline int adns_wire_is_pointer(const uint8_t * pos)
{
    return ((pos[0] & ADNS_WIRE_PTR) == ADNS_WIRE_PTR);
}

static inline uint8_t *adns_wire_next_label(const uint8_t * lp)
{
    if (unlikely(lp == NULL)) {
        return NULL;
    }

    return (uint8_t *) (lp + lp[0] + 1);
}

#endif 

