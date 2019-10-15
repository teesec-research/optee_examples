#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <errno.h>

#include <tee_client_api.h>
#include "tee_api_defines.h"

#include <runmem_ta.h>

#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

// #include <util.h> // https://github.com/OP-TEE/optee_os/blob/3.6.0/lib/libutils/ext/include/util.h
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
  exit(1);
}

static void usage(const char* notice){
		if(notice) printf("%s\n",notice);
        errx(EX_USAGE, "Usage:\nrunmem <num>\n");
}


static void report_return(uint32_t returnCode, uint32_t origin)
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
	printf("%8x (%s): %8x (%s)", origin, originText, returnCode, returnCodeText);
}

static void check_return(const char* fct, uint32_t res, uint32_t err_origin)
{
	if (res != TEEC_SUCCESS) {
		printf("%s failed with with origin and return code ", fct);
		report_return(res, err_origin);
		printf("\n");
        errx(1, "Fatal error.");
    }
}

void invoke (uint32_t cmd_id, char* cmd, uint64_t num)
{
	printf("%s: selected\n", cmd);
	TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = TA_RUNMEM_UUID;
    uint32_t err_origin;
    
    char input[512];
    char output[512];

	printf("%s: init context\n", cmd);
    res = TEEC_InitializeContext(NULL, &ctx);
    check_return("TEEC_InitializeContext", res, err_origin);

	printf("%s: open session\n", cmd);
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    check_return("TEEC_OpenSession", res, err_origin);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].value.a = (uint32_t)((uint64_t) num);
	op.params[0].value.b = (uint32_t)((uint64_t) num >> 32);
    op.params[2].tmpref.buffer = input;
    op.params[2].tmpref.size = sizeof(input);
    op.params[3].tmpref.buffer = output;
    op.params[3].tmpref.size = sizeof(output);
	
	printf("%s: invoke\n", cmd);
    res = TEEC_InvokeCommand(&sess, cmd_id, &op, &err_origin);
	printf("TEEC_InvokeCommand for command %s (%u) returned with with origin and return code ", cmd, cmd_id);
	report_return(res, err_origin);
	printf("\n");

	printf("%s: close session\n", cmd);
    TEEC_CloseSession(&sess);
	printf("%s: finalize context\n", cmd);
    TEEC_FinalizeContext(&ctx);
}
void overrun ()
{
    const char* cmd = "TA_RUNMEM_CMD_OVERRUN";
	printf("%s:\n", cmd);
	TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = TA_RUNMEM_UUID;
    uint32_t err_origin;
    
    char input[512];
    char output[512];

	printf("%s: init context\n", cmd);
    res = TEEC_InitializeContext(NULL, &ctx);
    check_return("TEEC_InitializeContext", res, err_origin);

	printf("%s: open session\n", cmd);
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    check_return("TEEC_OpenSession", res, err_origin);

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
    reg_pair_from_64(0x4001d000, &op.params[0].value.a, &op.params[0].value.b);
    reg_pair_from_64(0x00040000, &op.params[1].value.a, &op.params[1].value.b);
    op.params[2].tmpref.buffer = input;
    op.params[2].tmpref.size = sizeof(input);
    op.params[3].tmpref.buffer = output;
    op.params[3].tmpref.size = sizeof(output);
	
	printf("%s: invoke\n", cmd);
    res = TEEC_InvokeCommand(&sess, TA_RUNMEM_CMD_OVERRUN, &op, &err_origin);
	printf("TEEC_InvokeCommand for command %s (%u) returned with with origin and return code ", "TA_RUNMEM_CMD_OVERRUN", TA_RUNMEM_CMD_OVERRUN);
	report_return(res, err_origin);
	printf("\n");

	printf("%s: close session\n", cmd);
    TEEC_CloseSession(&sess);
	printf("%s: finalize context\n", cmd);
    TEEC_FinalizeContext(&ctx);
}

int main(int argc, char *argv[]) {
	// ==== INFO ====
	
	signal(SIGSEGV, handler);   // install our handler
    printf("compiletime "__DATE__ " "__TIME__ "\n");
    printf("%s %d\n", __FILE__, __LINE__);

	// ==== ARGS ====
	
    if (argc < 2)
		return usage("Too few arguments."),-1;
	
	errno = 0;
	uint64_t num = strtoll(argv[1], NULL, 0);
	if (errno)
		return err(EX_USAGE, "invalid <num>"), -1;
	
	// ==== INVOKE ====
	
	invoke(TA_RUNMEM_CMD_FAULT, "TA_RUNMEM_CMD_FAULT", 0);
	invoke(TA_RUNMEM_CMD_RUNMEM_STACK, "TA_RUNMEM_CMD_RUNMEM_STACK", num);
	invoke(TA_RUNMEM_CMD_RUNMEM_HEAP, "TA_RUNMEM_CMD_RUNMEM_HEAP", num);
	invoke(TA_RUNMEM_CMD_RUNMEM_DATA, "TA_RUNMEM_CMD_RUNMEM_DATA", num);
	invoke(TA_RUNMEM_CMD_RUNMEM_BSS, "TA_RUNMEM_CMD_RUNMEM_BSS", num);
	invoke(TA_RUNMEM_CMD_RUNMEM_TEXT, "TA_RUNMEM_CMD_RUNMEM_TEXT", num);
	invoke(TA_RUNMEM_CMD_RUNMEM_TEXT2, "TA_RUNMEM_CMD_RUNMEM_TEXT2", num);
	invoke(TA_RUNMEM_CMD_RUNMEM_HEAP_REMAP, "TA_RUNMEM_CMD_RUNMEM_HEAP_REMAP", num);
	invoke(TA_RUNMEM_CMD_RUNMEM_SHARED_INPUT, "TA_RUNMEM_CMD_RUNMEM_SHARED_INPUT", num);
	invoke(TA_RUNMEM_CMD_RUNMEM_SHARED_OUTPUT, "TA_RUNMEM_CMD_RUNMEM_SHARED_OUTPUT", num);
	invoke(TA_RUNMEM_CMD_PRINTF, "TA_RUNMEM_CMD_PRINTF", num);
	invoke(TA_RUNMEM_CMD_TEST_HEAP, "TA_RUNMEM_CMD_TEST_HEAP", num);
    overrun();

    return 0;
}

