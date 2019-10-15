#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <errno.h>

#include <tee_client_api.h>
#include "tee_api_defines.h"

#include <dumpmem_ta.h>

#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>


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
        errx(EX_USAGE, "Usage:\nreadmem <starting address> <length>\nreadmem 'fault'");
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
        errx(1, "Fatal error.");
    }
}

int main(int argc, char *argv[]) {
	// ==== INFO ====
	
	signal(SIGSEGV, handler);   // install our handler
    printf("compiletime "__DATE__ " "__TIME__ "\n");
    printf("%s %d\n", __FILE__, __LINE__);

	// ==== ARGS ====
	
    if (argc < 2)
		return usage("Too few arguments."),-1;
	bool runFault = false;
	if(strcmp(argv[1],"fault")==0)
		runFault = true;
	
	char *address = 0;
	size_t length = 0;
	if(!runFault)
	{
		if (argc < 3)
			return usage("Too few or wrong second parameter."),-1;
		//printf("%s %d\n", __FILE__, __LINE__);

		errno = 0;
		uint64_t input1 = strtoll(argv[1], NULL, 0);
		if (errno)
			return err(EX_USAGE, "invalid <starting address>"), -1;
		uint64_t input2 = strtoll(argv[2], NULL, 0);
		if (errno)
			return err(EX_USAGE, "invalid <length>"), -1;

		//printf("%s %d\n", __FILE__, __LINE__);

		address = (char *) input1;
		length = (size_t) input2;
	
		printf("using memory from 0x%016llx = %s0x%016llx = %zu = %s%lli\n",
			   (int64_t) address,
			   (int64_t) address < 0 ? "-" : "+",
			   (int64_t) address < 0 ? -(int64_t) address : (int64_t) address,
			   (int64_t) address,
			   (int64_t) address < 0 ? "-" : "+",
			   (int64_t) address < 0 ? -(int64_t) address : (int64_t) address);
		printf("using length 0x%016llx = %s0x%016llx = %zu = %s%lli\n",
				   (int64_t) length,
				   (int64_t) length < 0 ? "-" : "+",
				   (int64_t) length < 0 ? -(int64_t) length : (int64_t) length,
				   (int64_t) length,
				   (int64_t) length < 0 ? "-" : "+",
				   (int64_t) length < 0 ? -(int64_t) length : (int64_t) length);
	}
	
	// ==== INVOKE ====
	
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = TA_DUMPMEM_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    check_return("TEEC_InitializeContext", res, err_origin);

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    check_return("TEEC_OpenSession", res, err_origin);

    TEEC_Operation op;
	uint32_t cmd;
    memset(&op, 0, sizeof(op));

	if(runFault)
	{
		cmd = TA_DUMPMEM_CMD_FAULT;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
										 TEEC_NONE, TEEC_NONE);
	}
	else
	{
		cmd = TA_DUMPMEM_CMD_READMEM;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
										 TEEC_NONE, TEEC_NONE);

		op.params[0].value.a = (uint32_t)((uint64_t) address);
		op.params[0].value.b = (uint32_t)((uint64_t) address >> 32);
		op.params[1].value.a = (uint32_t)((uint64_t) length);
		op.params[1].value.b = (uint32_t)((uint64_t) length >> 32);

		//printf("Invoking TA with %x, %x\n", op.params[0].value.a, op.params[0].value.b);
	}
    res = TEEC_InvokeCommand(&sess, cmd, &op, &err_origin);
    check_return("TEEC_InvokeCommand", res, err_origin);
	
    printf("TA returned\n");

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);

    return 0;
}
