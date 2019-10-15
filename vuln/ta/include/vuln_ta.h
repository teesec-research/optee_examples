
#ifndef TA_VULN_H
#define TA_VULN_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_VULN_UUID \
	{ 0xca212bbe, 0x02b2, 0x422c, \
		{ 0x87,0x20,0xba,0x8f,0x5d,0x50,0x41,0x4b} }

/* The function IDs implemented in this TA */
#define TA_VULN_CMD_FIBUFNACCI		0
#define TA_VULN_CMD_PANIC		1
#define TA_VULN_CMD_NAME		2
#define TA_VULN_CMD_REMEMBER		3
#define TA_VULN_CMD_CHECK1		4
#define TA_VULN_CMD_CHECK2		5

#endif /*TA_VULN_H*/
