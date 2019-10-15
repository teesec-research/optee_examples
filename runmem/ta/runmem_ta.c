
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <runmem_ta.h>
#include <string.h>

#define SIGN_VERSION "2019-12-01-001"
#define SIGN() (IMSG("%s has been called, compiletime "__DATE__ " "__TIME__ "version " SIGN_VERSION "\n",__FUNCTION__))


/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void) {
    SIGN();
    
    char* page = tee_map_zi(1*4096, 0);
    IMSG("A page for no fun: %p",page);
    
    char* page2 = tee_map_zi(1*4096, 0);
    IMSG("Another page for fun: %p",page2);
    
    // tee_unmap(page, 1*4096);
    
    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void) {
    SIGN();
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4],
                                    void **sess_ctx) {
    SIGN();
    
    char* page = tee_map_zi(1*4096, 0);
    IMSG("A page for no fun: %p",page);
    
    char* page2 = tee_map_zi(1*4096, 0);
    IMSG("Another page for fun: %p",page2);
    
    // tee_unmap(page, 1*4096);
    
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);


    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    (void) &params;
    (void) &sess_ctx;

    return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void *sess_ctx) {
    SIGN();
    (void) &sess_ctx;
}













// begin https://raw.githubusercontent.com/OP-TEE/optee_os/c9826bf51538fa142ae83ffa9b3d29c5464bb285/ldelf/sys.c
// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <trace.h>
#include <utee_syscalls.h>
#include <pta_system.h>
#include <compiler.h>
#include <stddef.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_syscalls.h>


static TEE_Result invoke_sys_ta(uint32_t cmdid, struct utee_params *params)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t ret_orig = 0;

    uint32_t sess = 0;

    res = utee_open_ta_session(&(const TEE_UUID)PTA_SYSTEM_UUID,
                   0, NULL, &sess, &ret_orig);
    if (res)
        return res;
	

	return utee_invoke_ta_command(sess, 0, cmdid, params, &ret_orig);
}

TEE_Result sys_map_zi(size_t num_bytes, uint32_t flags, vaddr_t *va,
		      size_t pad_begin, size_t pad_end)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_params params = {
		.types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_VALUE_INOUT,
					 TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_NONE),
	};
	uint32_t r[2] = { 0 };

	params.vals[0] = num_bytes;
	params.vals[1] = flags;
	reg_pair_from_64(*va, r, r + 1);
	params.vals[2] = r[0];
	params.vals[3] = r[1];
	params.vals[4] = pad_begin;
	params.vals[5] = pad_end;

	res = invoke_sys_ta(PTA_SYSTEM_MAP_ZI, &params);
	if (!res)
		*va = reg_pair_to_64(params.vals[2], params.vals[3]);
	return res;
}

TEE_Result sys_set_prot(vaddr_t va, size_t num_bytes, uint32_t flags)
{
	struct utee_params params = {
		.types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_NONE,
					 TEE_PARAM_TYPE_NONE),
	};
	uint32_t r[2] = { 0 };

	params.vals[0] = num_bytes;
	params.vals[1] = flags;
	reg_pair_from_64(va, r, r + 1);
	params.vals[2] = r[0];
	params.vals[3] = r[1];

	return invoke_sys_ta(PTA_SYSTEM_SET_PROT, &params);
}
// end https://raw.githubusercontent.com/OP-TEE/optee_os/c9826bf51538fa142ae83ffa9b3d29c5464bb285/ldelf/sys.c







static char code_bss[8];
static char code_data[] =
		"\x00\xe4\x14\x91" // add     x0, x0, #1337
		"\xc0\x03\x5f\xd6" // ret
;
static char const * const code_text2  =
		"\x00\xe4\x14\x91" // add     x0, x0, #1337
		"\xc0\x03\x5f\xd6" // ret
;

long long int code_text(long long int num)
{
	num += 1337;
	return num;
}
	
    
    
    
    
    
    
    
    
    
    
static TEE_Result runmem(uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
    SIGN();

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_OUTPUT);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;







	// prepare stack
    char code_stack[] =
    {
        0x00,0xe4,0x14,0x91, // add     x0, x0, #1337
		0xc0,0x03,0x5f,0xd6 // ret
    };
	
    
    
    
    
    
	// prepare heap
	char* code_heap = TEE_Malloc(sizeof(code_stack), TEE_MALLOC_FILL_ZERO);
	if(!code_heap) return 1;
	memcpy(code_heap, /*:=*/ code_stack, sizeof(code_stack));
    
    // --------------------
    
	// prepare bss
	memcpy(code_bss, /*:=*/ code_stack, sizeof(code_stack));
    
    // --------------------
    
    // prepare shared
    if(params[2].memref.size < sizeof(code_stack))
        return TEE_ERROR_SHORT_BUFFER;
    char* input = (char*) params[2].memref.buffer;
    size_t inputLen = params[2].memref.size;
    
    if(params[3].memref.size < sizeof(code_stack))
        return TEE_ERROR_SHORT_BUFFER;
    char* output = (char*) params[3].memref.buffer;
    size_t outputLen = params[3].memref.size;
	
    memcpy(input, /*:=*/ code_stack, sizeof(code_stack));
	memcpy(output, /*:=*/ code_stack, sizeof(code_stack));
    
    TEE_Result setprotres; 
    if ( setprotres = sys_set_prot((uintptr_t)input & ~((uintptr_t)0x1000-1), 4096, PTA_SYSTEM_MAP_FLAG_EXECUTABLE)
        != TEE_SUCCESS)
    {
        IMSG("set_prot(input=%p,0x%zx,0x%x) failed", (void*) ((uintptr_t)input & ~((uintptr_t)0x1000-1)), (size_t)4096, (int)PTA_SYSTEM_MAP_FLAG_EXECUTABLE);
    }
    if ( setprotres = sys_set_prot((uintptr_t)output & ~((uintptr_t)0x1000-1), 4096 , PTA_SYSTEM_MAP_FLAG_EXECUTABLE)
        != TEE_SUCCESS)
    {
        IMSG("set_prot(output=%p,0x%zx,0x%x) failed", (void*) ((uintptr_t)output & ~((uintptr_t)0x1000-1)), (size_t)4096, (int)PTA_SYSTEM_MAP_FLAG_EXECUTABLE);
    }
	
    // --------------------
    
	// data is already prepared
    
    // --------------------
    
	// text2 is already prepared

    // --------------------
    
    // prepare heap_remap
    
    char* code_heap_remap = tee_map_zi(4096, 0); // these are not access flags, we can expect rw- memory without --x
    if ( !code_heap_remap) {
        IMSG("code_heap_remap became null pointer");
        return TEE_ERROR_GENERIC;
    }
    // write there
	memcpy(code_heap_remap, /*:=*/ code_stack, sizeof(code_stack));
    // TEE_Result sys_set_prot(vaddr_t va, size_t num_bytes, uint32_t flags)
    if ( sys_set_prot(code_heap_remap, 4096, PTA_SYSTEM_MAP_FLAG_EXECUTABLE)
        != TEE_SUCCESS)
    {
        IMSG("code_heap_remap set_prot failed");
    }




	

    uint64_t num = (uint64_t) ((uint64_t) params[0].value.a + ((uint64_t) params[0].value.b << 32));
    IMSG("Number is %lu", num);
    
    
	
    long long int (*func)(long long int);
	switch(cmd_id) {
		case TA_RUNMEM_CMD_RUNMEM_STACK: func = code_stack; IMSG("Command is TA_RUNMEM_CMD_RUNMEM_STACK"); break; 
		case TA_RUNMEM_CMD_RUNMEM_HEAP: func = code_heap; IMSG("Command is TA_RUNMEM_CMD_RUNMEM_HEAP"); break;
		case TA_RUNMEM_CMD_RUNMEM_DATA: func = code_data; IMSG("Command is TA_RUNMEM_CMD_RUNMEM_DATA"); break;
		case TA_RUNMEM_CMD_RUNMEM_BSS: func = code_bss; IMSG("Command is TA_RUNMEM_CMD_RUNMEM_BSS"); break;
		case TA_RUNMEM_CMD_RUNMEM_TEXT: func = code_text; IMSG("Command is TA_RUNMEM_CMD_RUNMEM_TEXT"); break;
		case TA_RUNMEM_CMD_RUNMEM_TEXT2: func = code_text2; IMSG("Command is TA_RUNMEM_CMD_RUNMEM_TEXT2"); break;
		case TA_RUNMEM_CMD_RUNMEM_HEAP_REMAP: func = code_heap_remap; IMSG("Command is TA_RUNMEM_CMD_RUNMEM_HEAP_REMAP"); break;
		case TA_RUNMEM_CMD_RUNMEM_SHARED_INPUT: func = input; IMSG("Command is TA_RUNMEM_CMD_RUNMEM_SHARED_INPUT"); break;
		case TA_RUNMEM_CMD_RUNMEM_SHARED_OUTPUT: func = output; IMSG("Command is TA_RUNMEM_CMD_RUNMEM_SHARED_OUTPUT"); break;
		default: IMSG("Unknown code %u", cmd_id); return TEE_ERROR_BAD_PARAMETERS;
	}
	
	IMSG("Raw assembly is:");
	char* address = (char*)func;
	IMSG("    %16p: %02hhx %02hhx  %02hhx %02hhx", (void*)address, address[0], address[1], address[2], address[3]); address+=4;
	IMSG("    %16p: %02hhx %02hhx  %02hhx %02hhx", (void*)address, address[0], address[1], address[2], address[3]); address+=4;
	IMSG("    %16p: %02hhx %02hhx  %02hhx %02hhx", (void*)address, address[0], address[1], address[2], address[3]); address+=4;
	
	
	IMSG("Calling %p to increment by 1337", (void*)func);
	num = func(num);
	
	IMSG("Number is %lu", num);
	
	TEE_Free(code_heap);
    return TEE_SUCCESS;
}

   
static TEE_Result test_heap(uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
    SIGN();
    char *h32a, *h32b, *h32c, *h32d, *h32e, *h32f;
    IMSG("malloc h32a %p", h32a = TEE_Malloc(32,0));
    IMSG("malloc h32b %p", h32b = TEE_Malloc(32,0));
    IMSG("malloc h32c %p", h32c = TEE_Malloc(32,0));
    TEE_Free(h32a); IMSG("free h32a %p", h32a);
    TEE_Free(h32c); IMSG("free h32c %p", h32c);
    IMSG("malloc h32d %p", h32d = TEE_Malloc(32,0));
    IMSG("malloc h32e %p", h32e = TEE_Malloc(32,0));
    IMSG("malloc h32f %p", h32f = TEE_Malloc(32,0));
    return TEE_SUCCESS;
}  
static TEE_Result test_printf(uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
    printf("x1: %llx, x2: %llx, x3: %llx, x4: %llx, x5: %llx, x6: %llx, x7: %llx, x8 (ind): %llx",
        0x1011121314151617,
        0x2021222324252627,
        0x3031323334353637,
        0x4041424344454647,
        0x5051525354555657,
        0x6061626364656667,
        0x7071727374757677,
        0x8081828384858687);
    // registers are stored during puts, I hope, and restored after to avoid information leaks cross-ta
    // see thread_svc_regs https://github.com/OP-TEE/optee_os/blob/10ed1717872ee2cb6054df7c362283cb24c102e5/core/arch/arm/include/kernel/thread.h#L172
    // puts does not seem to be a bulky pta call, since there is syscall_log defined as tee_svc_syscall_table[1]
    // Panic with less setting x0  
    
    
            return *((char*)NULL);
            // Does not work:
            /*
                I/TA: has been called, compiletime Oct 15 2019 13:58:44version 2019-10-06-002
                I/TA: has been called, compiletime Oct 15 2019 13:58:44version 2019-10-06-002
                x1: 1011121314151617, x2: 2021222324252627, x3: 3031323334353637, x4: 4041424344454647, x5: 5051525354555657, x6: 6061
                E/TC:? 0
                E/TC:? 0 User TA data-abort at address 0x0 (translation fault)
                E/TC:? 0  esr 0x92000005  ttbr0 0x200000e17a020   ttbr1 0x00000000   cidr 0x0
                E/TC:? 0  cpu #1          cpsr 0x80000100
                E/TC:? 0  x0  0000000000000000 x1  00000000000000b4
                E/TC:? 0  x2  0000000000000000 x3  0000000000000010
                E/TC:? 0  x4  0000000040028bdd x5  0000000000000000
                E/TC:? 0  x6  00000000fffffff0 x7  0000000000000020
                E/TC:? 0  x8  0000000000000001 x9  000000004001af8d
                E/TC:? 0  x10 0000000040012650 x11 0000000040005f04
                E/TC:? 0  x12 0000000000000fff x13 0000000040028bc8
                E/TC:? 0  x14 0000000000000000 x15 0000000000000000
                E/TC:? 0  x16 000000000e11a45c x17 e894f12d00000000
                E/TC:? 0  x18 1825380200000000 x19 0000000040027430
                E/TC:? 0  x20 000000004001c000 x21 0000000040028f30
                E/TC:? 0  x22 0000000000000011 x23 0000000040028f80
                E/TC:? 0  x24 0000000000000011 x25 000000000e16a880
                E/TC:? 0  x26 0000000040028f88 x27 0000000000000011
                E/TC:? 0  x28 0000000000000000 x29 0000000040028e70
                E/TC:? 0  x30 0000000040010308 elr 000000004001030c
                E/TC:? 0  sp_el0 0000000040028e60
                E/LD:  Status of TA 2ddefbb6-c357-4f36-ab16-2b2a75add77e
                E/LD:   arch: aarch64
                E/LD:  region  0: va 0x40004000 pa 0x0e300000 size 0x002000 flags rw-s (ldelf)
                E/LD:  region  1: va 0x40006000 pa 0x0e302000 size 0x006000 flags r-xs (ldelf)
                E/LD:  region  2: va 0x4000c000 pa 0x0e308000 size 0x001000 flags rw-s (ldelf)
                E/LD:  region  3: va 0x4000d000 pa 0x0e309000 size 0x002000 flags rw-s (ldelf)
                E/LD:  region  4: va 0x4000f000 pa 0x0e319000 size 0x001000 flags r--s
                E/LD:  region  5: va 0x40010000 pa 0x00001000 size 0x00c000 flags r-xs [0]
                E/LD:  region  6: va 0x4001c000 pa 0x0000d000 size 0x00c000 flags rw-s [0]
                E/LD:  region  7: va 0x40028000 pa 0x0e30b000 size 0x001000 flags rw-s (stack)
                E/LD:   [0] 2ddefbb6-c357-4f36-ab16-2b2a75add77e @ 0x40010000
                E/LD:  Call stack:
                E/LD:   0x000000004001030c
                E/LD:   0x00000000400128fc
                E/LD:   0x0000000040010674
                E/LD:   0x000000000e103324
            */
}





static TEE_Result test_overrun(uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
    SIGN();
    
    char* page = tee_map_zi(1*4096, 0);
    IMSG("A page for no fun: %p",page);
    
    char* page2 = tee_map_zi(1*4096, 0);
    IMSG("Another page for fun: %p",page2);
    
    
    char* start = reg_pair_to_64(params[0].value.a, params[0].value.b);
    size_t size = reg_pair_to_64(params[1].value.a, params[1].value.b);
    char* end = start + size;
    for(char* p = start; p < end; p++)
        *p=0; // overwrite everything with zeroes.
        
    IMSG("FINISHED.\n");
    IMSG("REALLY.\n");
    IMSG("NOTHING TO SEE HERE.\n");
    return *((char*)NULL); // SEGFAULT!
}




static TEE_Result test_panic(uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
    SIGN();
    TEE_Result res = tee_unmap((void*)0x40010000,0x00c000);
    DMSG("NOT DEAD. YET: 0x%x", (unsigned int)res);
    return *((char*)NULL); // SEGFAULT!
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    (void) &sess_ctx;

    switch (cmd_id) {
        case TA_RUNMEM_CMD_RUNMEM_STACK:
        case TA_RUNMEM_CMD_RUNMEM_HEAP:
        case TA_RUNMEM_CMD_RUNMEM_DATA:
        case TA_RUNMEM_CMD_RUNMEM_BSS:
        case TA_RUNMEM_CMD_RUNMEM_TEXT:
        case TA_RUNMEM_CMD_RUNMEM_TEXT2:
        case TA_RUNMEM_CMD_RUNMEM_HEAP_REMAP:
		case TA_RUNMEM_CMD_RUNMEM_SHARED_INPUT: 
		case TA_RUNMEM_CMD_RUNMEM_SHARED_OUTPUT:
            return runmem(cmd_id, param_types, params);
        case TA_RUNMEM_CMD_TEST_HEAP:
            return test_heap(cmd_id, param_types, params);
        case TA_RUNMEM_CMD_PRINTF:
            return test_printf(cmd_id, param_types, params);
        case TA_RUNMEM_CMD_FAULT:
            return test_panic(cmd_id, param_types, params);
        case TA_RUNMEM_CMD_OVERRUN:
            return test_overrun(cmd_id, param_types, params);  
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
