
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <dumpmem_ta.h>
#include <string.h>
#include <malloc.h>

#define SIGN() (IMSG("has been called, compiletime "__DATE__ " "__TIME__ "\n"))


/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void) {
    SIGN();

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

extern uint8_t ta_heap[];
extern const size_t ta_heap_size;
extern struct ta_head ta_head;

#include <sys/queue.h>
struct ta_session {
	uint32_t session_id;
	void *session_ctx;
	TAILQ_ENTRY(ta_session) link;
};


static TEE_Result readmem(uint32_t param_types,
                          TEE_Param params[4]) {
    SIGN();

    char addr1[1];
	static int bss_fake;
	static int data_fake = 0;
    
	void *addr2 = TEE_Malloc(1, TEE_MALLOC_FILL_ZERO);
    TEE_Free(addr2);
    
    const char* loremipsum = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";
    char libuf[strlen(loremipsum)+1];
	
    // size_t curalloc, totfree, maxfree; long nget, nrel;
    // bstats(&curalloc, &totfree, &maxfree, &nget, &nrel, malloc_ctx.poolset);
    // IMSG("bstats(curalloc=%zx, totfree=%zx, maxfree=%zx, nget=%zx, nrel=%zx)", curalloc, totfree, maxfree, nget, nrel);
    
    IMSG(".stack is around %p", (void*)addr1);
    IMSG("ipsum will be at %p", (void*)libuf);
    IMSG(".heap is around %p", (void*)addr2);
    
    IMSG("ta_head is at %p", (void*)&ta_head);
    void *ptr;
    IMSG("ta_heap is at %p", (void*)ta_heap);
    IMSG("ta_heap_size is %zx", (size_t)ta_heap_size);
    IMSG("sizeof(struct ta_session) is %zx", (size_t)sizeof(struct ta_session));
    ptr = malloc(16); 
    IMSG("malloc(16) is at %p", (void*)ptr);
    free(ptr);
    ptr = malloc(1); 
    IMSG("malloc(1) is at %p", (void*)ptr);
    free(ptr);
    ptr = malloc(0x100); 
    IMSG("malloc(0x100) is at %p", (void*)ptr);
    free(ptr);
    
    
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wpedantic"
	//  warning: ISO C forbids conversion of function pointer to object pointer type [-Wpedantic]
    IMSG(".text is around %p",  (void*)readmem);
	#pragma GCC diagnostic pop
    IMSG(".bss is around %p",  (void*)& bss_fake);
    IMSG(".data is around %p", (void*)& data_fake);


    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;


    //IMSG("got %x, %x", params[0].value.a, params[0].value.b);
    char *address = (char *) ((uint64_t) params[0].value.a + ((uint64_t) params[0].value.b << 32));
    size_t length = (size_t) ((uint64_t) params[1].value.a + ((uint64_t) params[1].value.b << 32));
    IMSG("reading memory from 0x%016lx = %s0x%016lx = %zu = %s%li",
         (int64_t) address,
         (int64_t) address < 0 ? "-" : "+",
         (int64_t) address < 0 ? (uint64_t) -(int64_t) address : (uint64_t) address,
         (int64_t) address,
         (int64_t) address < 0 ? "-" : "+",
         (int64_t) address < 0 ? -(int64_t) address : (int64_t) address);

    IMSG("read own %i", TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ, address, 1));
    IMSG("read any %i", TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER, address, 1));
    IMSG("write own %i", TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_WRITE, address, 1));
    IMSG("write any %i",
         TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_WRITE | TEE_MEMORY_ACCESS_ANY_OWNER, address, 1));

    for (size_t i = 0; i < length; i += 32) {
        if (TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER, &address[i], 32) ==
            TEE_SUCCESS)
            IMSG("%16p: %02x%02x%02x%02x %02x%02x%02x%02x  %02x%02x%02x%02x %02x%02x%02x%02x    %02x%02x%02x%02x %02x%02x%02x%02x  %02x%02x%02x%02x %02x%02x%02x%02x",
                 &address[i],
                 (unsigned char) address[i + 0x00],
                 (unsigned char) address[i + 0x01],
                 (unsigned char) address[i + 0x02],
                 (unsigned char) address[i + 0x03],
                 (unsigned char) address[i + 0x04],
                 (unsigned char) address[i + 0x05],
                 (unsigned char) address[i + 0x06],
                 (unsigned char) address[i + 0x07],
                 (unsigned char) address[i + 0x08],
                 (unsigned char) address[i + 0x09],
                 (unsigned char) address[i + 0x0a],
                 (unsigned char) address[i + 0x0b],
                 (unsigned char) address[i + 0x0c],
                 (unsigned char) address[i + 0x0d],
                 (unsigned char) address[i + 0x0e],
                 (unsigned char) address[i + 0x0f],
                 (unsigned char) address[i + 0x10],
                 (unsigned char) address[i + 0x11],
                 (unsigned char) address[i + 0x12],
                 (unsigned char) address[i + 0x13],
                 (unsigned char) address[i + 0x14],
                 (unsigned char) address[i + 0x15],
                 (unsigned char) address[i + 0x16],
                 (unsigned char) address[i + 0x17],
                 (unsigned char) address[i + 0x18],
                 (unsigned char) address[i + 0x19],
                 (unsigned char) address[i + 0x1a],
                 (unsigned char) address[i + 0x1b],
                 (unsigned char) address[i + 0x1c],
                 (unsigned char) address[i + 0x1d],
                 (unsigned char) address[i + 0x1e],
                 (unsigned char) address[i + 0x1f]
            );
    }

    // write some data on the stack
    strncpy(libuf, loremipsum, strlen(loremipsum)+1);
    
    return TEE_SUCCESS;
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
        case TA_DUMPMEM_CMD_READMEM:
            return readmem(param_types, params);
        case TA_DUMPMEM_CMD_FAULT:
            return *((char*)NULL); // SEGFAULT!
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
