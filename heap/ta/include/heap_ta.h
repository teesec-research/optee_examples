
#ifndef TA_HEAP_H
#define TA_HEAP_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_HEAP_UUID \
	{ 0xca212bbe, 0x02b2, 0x422c, \
		{ 0x87,0x20,0xba,0x8f,0x5d,0x50,0x41,0x4c} }

/* The function IDs implemented in this TA */
enum cmd {
	TA_HEAP_CMD_PANIC,
	TA_HEAP_CMD_OPEN_SESSION,
	TA_HEAP_CMD_CLOSE_SESSION,
	TA_HEAP_CMD_LOGIN,
	TA_HEAP_CMD_TELL_ME,
	TA_HEAP_CMD_SWITCH_USER,
};

#endif /*TA_HEAP_H*/
