#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

// #include <utee_syscalls.h>
#include <vuln_ta.h>
#include <string.h>
#include <util.h>
#include <stdlib.h>

const char* SECRET = "09 F9 11 02 9D 74 E3 5B D8 41 56 C5 63 56 88 C0";
bool PRINTSECRET = false;

/* obsolete in newer optees
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
*/

#define SIGN() (DMSG("has been called, compiletime "__DATE__ " "__TIME__ "\n"))

TEE_Result TA_CreateEntryPoint(void)
{
    SIGN();
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    SIGN();
}

void hint(char iterations);
void hint(char iterations)
{
	DMSG("Iteration: %i", iterations);
}

/**
Intended to avoid GCC optimizing away recursion, which it can't due to referenced memory arrays.
textlen: like strlen, not a size.
*/
char* fibufnacci(const char* text, size_t textlen, const char* textprev, size_t textprevlen, char iterations);
char* fibufnacci(const char* text, size_t textlen, const char* textprev, size_t textprevlen, char iterations)
{
    SIGN();
	DMSG("With params: %p, %zu, %p, %zu, %i", text, textlen, textprev, textprevlen, (int)iterations);
	DMSG("With values: %s, %s", text, textprev); /*vuln*/
	char tmp[128];  
	if(iterations == 0)
	{
		return strdup(text);
	}
	else
	{
		memcpy(&tmp[0], text, textlen); /*vuln*/
		memcpy(&tmp[textlen], textprev, textprevlen); /*vuln*/
		
		// char* address = (char*)tmp;
		// IMSG("    %16p: %02hhx %02hhx  %02hhx %02hhx", (void*)address, address[0], address[1], address[2], address[3]); address+=4;
		// IMSG("    %16p: %02hhx %02hhx  %02hhx %02hhx", (void*)address, address[0], address[1], address[2], address[3]); address+=4;
		// IMSG("    %16p: %02hhx %02hhx  %02hhx %02hhx", (void*)address, address[0], address[1], address[2], address[3]); address+=4;
	
		
		// tmp[textlen+textprevlen-1] += 1;
		// if (tmp[textlen+textprevlen-1] > 126)
			// tmp[textlen+textprevlen] -= ' ';
		
		tmp[textlen+textprevlen] = 0;
	}
	hint(iterations);
	DMSG("%s", tmp);
	return fibufnacci(tmp, textlen+textprevlen, text, textlen, iterations-1);
}

static void includeLibs(void);

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

    SIGN();
	includeLibs();

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	SIGN();
}

static TEE_Result call_fibufnacci(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES
        (
            TEE_PARAM_TYPE_MEMREF_INOUT, // input a buffer, output with buffer size
            TEE_PARAM_TYPE_VALUE_INOUT, // input a size (input a buffer is longer than input)
            TEE_PARAM_TYPE_MEMREF_INPUT, // input b with size
            TEE_PARAM_TYPE_VALUE_INPUT // iterations
        );

	SIGN();

	// oops, I forgot...
	if (param_types != exp_param_types)
    {} // return TEE_ERROR_BAD_PARAMETERS;

	DMSG("Hello, I'm VULN!\n");
	DMSG("fibufnacci is at %p", (void*)fibufnacci);
	DMSG("memcpy is at %p", (void*)memcpy);
	DMSG("TA_OpenSessionEntryPoint is at %p", (void*)TA_OpenSessionEntryPoint);
	DMSG("TEE_InvokeTACommand is at %p", (void*)TEE_InvokeTACommand);
	// DMSG("utee_log is at %p", (void*)utee_log);
	// DMSG("utee_return is at %p", (void*)utee_return);
	DMSG("SECRET is at %p", (void*)SECRET);
	DMSG("TEE_ReadObjectData is at %p", (void*)TEE_ReadObjectData);
	
	//fibufnacci("a",1,"a",1, 6);
	
	size_t size0 = reg_pair_to_64(params[1].value.a,params[1].value.b);
	size_t size2 = params[2].memref.size;
    size_t iterations = reg_pair_to_64(params[3].value.a,params[3].value.b);
	
	// INOUT memrefs might be larger than we shall use (to fit a longer result, too), but must not be shorter.
	if(size0 > params[0].memref.size)
	{		
		DMSG("refusing short input buffer a with size %u!", params[0].memref.size);
		return TEE_ERROR_SHORT_BUFFER;
	}
	
	char* result = fibufnacci
	(
		(char*)params[0].memref.buffer,size0,
		(char*)params[2].memref.buffer,size2,
		iterations
	);
	
	if(strlen(result)+1>params[0].memref.size)
	{
		DMSG("refusing short output buffer!");
		TEE_Free(result);
		return TEE_ERROR_SHORT_BUFFER;
	}
	strcpy((char*)params[0].memref.buffer, result);
	TEE_Free(result);
	if (PRINTSECRET)
	{
		DMSG("%s",SECRET);
	}
	return TEE_SUCCESS;
}

void* memdup(const void* mem, size_t size);
void* memdup(const void* mem, size_t size) { 
   void* out = malloc(size);

   if(out != NULL)
       memcpy(out, mem, size);

   return out;
}

// allows the client to provide a string for later use.
static char* session_name;
static TEE_Result call_strdup(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES
        (
            TEE_PARAM_TYPE_MEMREF_INPUT, // string to store here
            TEE_PARAM_TYPE_NONE, // output its address (insecure!)
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE
        );

	SIGN();

	// oops, I forgot...
	if (param_types != exp_param_types)
		{} // return TEE_ERROR_BAD_PARAMETERS;
        
    if(session_name != NULL)
        free(session_name);
        
    // use memdup/memcpy, since strdup is insecure here! strndup? Never heard of...
    session_name = memdup(params[0].memref.buffer, params[0].memref.size); 
    IMSG("Got session name %s at %p", session_name, session_name); // overflow again!
	return TEE_SUCCESS;
}

static char const remember_id[] = "storage:b39193c4-bff6-4325-9598-0753f0ec1fd2"; // some magic string shorter than 64 bytes

static TEE_Result call_remember(uint32_t param_types,
	TEE_Param params[4]){
    
	uint32_t exp_param_types = TEE_PARAM_TYPES
        (
            TEE_PARAM_TYPE_MEMREF_INPUT, // string to store here
            TEE_PARAM_TYPE_NONE, // output its address (insecure!)
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE
        );

	SIGN();

	// oops, I forgot...
	if (param_types != exp_param_types)
		{} // return TEE_ERROR_BAD_PARAMETERS;
        
        
    TEE_Result res;
    TEE_ObjectHandle handle;
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE, // storage id
        remember_id, sizeof(remember_id),  // object id
        0 | // access flags
        0 | // sharing flags
        TEE_DATA_FLAG_OVERWRITE, // overwrite if present
        NULL, // attributes, here pure data object TEE_TYPE_DATA
        params[0].memref.buffer, params[0].memref.size, // initial data contents
        &handle // output
        );
        
    if(res != TEE_SUCCESS)
    {
        DMSG("Remember failed, code: %u", (unsigned int)res);
        return res;
    }
    
    TEE_CloseObject(handle);
    return TEE_SUCCESS;
}


static TEE_Result call_check(uint32_t param_types,
	TEE_Param params[4]){
    
	uint32_t exp_param_types = TEE_PARAM_TYPES
        (
            TEE_PARAM_TYPE_MEMREF_INPUT, // string to store here
            TEE_PARAM_TYPE_NONE, // output its address (insecure!)
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE
        );

	SIGN();

	// oops, I forgot...
	if (param_types != exp_param_types)
		{} // return TEE_ERROR_BAD_PARAMETERS;
        
    
    TEE_Result res;
    TEE_ObjectHandle handle;
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE, // storage id
        remember_id, sizeof(remember_id),  // object id
        TEE_DATA_FLAG_ACCESS_READ | // access flags
        TEE_DATA_FLAG_SHARE_READ, // sharing flags
        &handle // output
        );
        
    if(res != TEE_SUCCESS)
    {
        DMSG("Open failed, code: %u", (unsigned int)res);
        return res;
    }
    
    // spec says, we shall copy input parameters, so we do.
    char* input = memdup(params[0].memref.buffer, params[0].memref.size); // Generate hash instead? Not yet implemented. ;)
    //size_t size;
    uint32_t size; // yes, the API spec forgot 64bit here (amongst other locations, too)
    
    // the input buffer is now free. ;)
    // yes, this is wrong, it does not return an error on the size mismatch. feed it a zero size, and you'll get the secret too.
    // this means: reading is difficult, since there is no simple eof-check, except getting object-info inbefore.
    // No idea how well a correct implementation handles shared data objects written while read, probably not at all. However, there is an atomic replace available.
    res = TEE_ReadObjectData(handle, params[0].memref.buffer, params[0].memref.size, &size);
    if(res != TEE_SUCCESS)
    {
        DMSG("Read failed, code: %u", (unsigned int)res);
        return res;
    }
    
    if(size != params[0].memref.size)
    {
        DMSG("Wrong size, guess again!");
        return TEE_ERROR_GENERIC;
    }
    // has a constant-time implementation, but only in OPTEE, not mandated by TEE API standard. Enough for now. ;)
    if(TEE_MemCompare(params[0].memref.buffer, input, size) != 0)
    {
        DMSG("Wrong contents, guess again!");
        return TEE_ERROR_GENERIC;
    }
    DMSG("SUCCESS. Here, have a secret: %s", SECRET);
    free(input);
    
    
    TEE_CloseObject(handle);
    return TEE_SUCCESS;
}

// "more secure" implementation. Does not expose to shared memory.
static TEE_Result call_check2(uint32_t param_types,
	TEE_Param params[4]){
    
	uint32_t exp_param_types = TEE_PARAM_TYPES
        (
            TEE_PARAM_TYPE_MEMREF_INPUT, // string to store here
            TEE_PARAM_TYPE_NONE, // output its address (insecure!)
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE
        );

	SIGN();

	// oops, I forgot... again and again. ;)
	if (param_types != exp_param_types)
		{} // return TEE_ERROR_BAD_PARAMETERS;
        
    
    TEE_Result res;
    TEE_ObjectHandle handle;
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE, // storage id
        remember_id, sizeof(remember_id),  // object id
        TEE_DATA_FLAG_ACCESS_READ | // access flags
        TEE_DATA_FLAG_SHARE_READ, // sharing flags
        &handle // output
        );
        
    if(res != TEE_SUCCESS)
    {
        DMSG("Open failed, code: %u", (unsigned int)res);
        return res;
    }
    
    // spec says, we shall copy input parameters, so we do.
    char reference[256];
    //size_t size;
    uint32_t size; // yes, the API spec forgot 64bit here (amongst other locations, too)
    
    res = TEE_ReadObjectData(handle, reference, sizeof(reference), &size);
    if(res != TEE_SUCCESS)
    {
        DMSG("Read failed, code: %u", (unsigned int)res);
        return res;
    }
    
    if(size != params[0].memref.size)
    {
        DMSG("Wrong size, guess again!");
        return TEE_ERROR_GENERIC;
    }
    if(TEE_MemCompare(params[0].memref.buffer, reference, size) != 0)
    {
        DMSG("Wrong contents, guess again!");
        return TEE_ERROR_GENERIC;
    }
    DMSG("SUCCESS. Here, have a secret: %s", SECRET);
    
    
    TEE_CloseObject(handle);
    return TEE_SUCCESS;
}



/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
    // char buffer[1024]; // diagnostics
	(void)&sess_ctx; /* Unused parameter */
	SIGN();
	if(session_name) IMSG("Session Name: %s", session_name);
	switch (cmd_id)
	{
		case TA_VULN_CMD_FIBUFNACCI:
			return call_fibufnacci(param_types, params);
		case TA_VULN_CMD_NAME:
			return call_strdup(param_types, params);
		case TA_VULN_CMD_REMEMBER:
			return call_remember(param_types, params);
		case TA_VULN_CMD_CHECK1:
			return call_check(param_types, params);
		case TA_VULN_CMD_CHECK2:
			return call_check2(param_types, params);
			
		case TA_VULN_CMD_PANIC:
			return *((TEE_Result*)NULL);
			
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}

// =============================================================================
// ROP EXTRA CODE

struct animation_definition 
{
    uint64_t color_r_amp, color_g_amp, color_b_amp,
        color_r_wavelength, color_g_wavelength, color_b_wavelength,
        color_r_phase, color_g_phase, color_b_phase;
};

// ruft keine anderen Methoden mit mehr als einem Parameter (x0) auf, x1 ff. bleiben unverändert; hat genug Parameter, um alle Register zu setzen.
uint64_t calc_animation
    (
        uint64_t color_r_amp, uint64_t color_g_amp, uint64_t color_b_amp,
        uint64_t color_r_wavelength, uint64_t color_g_wavelength, uint64_t color_b_wavelength,
        uint64_t color_r_phase, uint64_t color_g_phase, uint64_t color_b_phase
    );
uint64_t calc_animation
    (
        uint64_t color_r_amp, uint64_t color_g_amp, uint64_t color_b_amp,
        uint64_t color_r_wavelength, uint64_t color_g_wavelength, uint64_t color_b_wavelength,
        uint64_t color_r_phase, uint64_t color_g_phase, uint64_t color_b_phase
    ) 
{ 
    static uint64_t time = 0;
    unsigned char r,g,b,a =0;
    r = (time - color_r_phase) % color_r_wavelength > color_r_wavelength/2 ? color_r_amp%255 : 0;
    g = (time - color_g_phase) % color_g_wavelength > color_g_wavelength/2 ? color_g_amp%255 : 0;
    b = (time - color_b_phase) % color_b_wavelength > color_b_wavelength/2 ? color_b_amp%255 : 0;
    time++;
    return ((uint64_t)r<<24) + ((uint64_t)g<<16) + ((uint64_t)b<<8) + ((uint64_t)a<<0);
}

// liest Daten aus einer Speicheradresse, und schiebt diese für den Aufruf in x1 ff. -- verändert diese danach aber nicht mehr und kehrt ohne Gelegenheit eines Segfaults sofort zurück.
uint64_t animate
    (struct animation_definition* animation);
uint64_t animate
    (struct animation_definition* animation)
{
    return calc_animation(
        animation->color_r_amp, animation->color_g_amp, animation->color_b_amp,
        animation->color_r_wavelength, animation->color_g_wavelength, animation->color_b_wavelength, 
        animation->color_r_phase, animation->color_g_phase, animation->color_b_phase
    );
}
bool calc_animation2_enable_debug = false; // nonstatic intended.
// ruft keine anderen Methoden mit mehr als einem Parameter (x0) auf, x1 ff. bleiben unverändert; hat genug Parameter, um alle Register zu setzen.
uint64_t calc_animation2
    (
        uint64_t color_r_amp, uint64_t color_g_amp, uint64_t color_b_amp,
        uint64_t color_r_wavelength, uint64_t color_g_wavelength, uint64_t color_b_wavelength,
        uint64_t color_r_phase, uint64_t color_g_phase, uint64_t color_b_phase
    ) ;
uint64_t calc_animation2
    (
        uint64_t color_r_amp, uint64_t color_g_amp, uint64_t color_b_amp,
        uint64_t color_r_wavelength, uint64_t color_g_wavelength, uint64_t color_b_wavelength,
        uint64_t color_r_phase, uint64_t color_g_phase, uint64_t color_b_phase
    ) 
{ 
    static uint64_t time = 0;
    unsigned char r,g,b,a=0;
    r = (time - color_r_phase) % color_r_wavelength > color_r_wavelength/2 ? color_r_amp%255 : 0;
    g = (time - color_g_phase) % color_g_wavelength > color_g_wavelength/2 ? color_g_amp%255 : 0;
    b = (time - color_b_phase) % color_b_wavelength > color_b_wavelength/2 ? color_b_amp%255 : 0;
    time++;
    if (calc_animation2_enable_debug)
        printf("I'm here and you can't use x0--x8! %lu %lu %lu %lu %lu %lu %lu %lu %lu",
            color_r_amp, color_g_amp, color_b_amp,
            color_r_wavelength, color_g_wavelength, color_b_wavelength,
            color_r_phase, color_g_phase, color_b_phase
        );
    return ((uint64_t)r<<24) + ((uint64_t)g<<16) + ((uint64_t)b<<8) + ((uint64_t)a<<0);
}

// liest Daten aus einer Speicheradresse, und schiebt diese für den Aufruf in x1 ff. -- verändert diese danach aber nicht mehr und kehrt ohne Gelegenheit eines Segfaults sofort zurück.
uint64_t animate2
    (struct animation_definition* animation);
uint64_t animate2
    (struct animation_definition* animation)
{
    return calc_animation(
        animation->color_r_amp, animation->color_g_amp, animation->color_b_amp,
        animation->color_r_wavelength, animation->color_g_wavelength, animation->color_b_wavelength, 
        animation->color_r_phase, animation->color_g_phase, animation->color_b_phase
    );
}
bool calc_animation3_enable_debug = false; // nonstatic intended.
// ruft keine anderen Methoden mit mehr als einem Parameter (x0) auf, x1 ff. bleiben unverändert; hat genug Parameter, um alle Register zu setzen.
void dump_animation_values
    (
        uint64_t color_r_amp, uint64_t color_g_amp, uint64_t color_b_amp,
        uint64_t color_r_wavelength, uint64_t color_g_wavelength, uint64_t color_b_wavelength,
        uint64_t color_r_phase, uint64_t color_g_phase, uint64_t color_b_phase
    ) ;
void dump_animation_values
    (
        uint64_t color_r_amp, uint64_t color_g_amp, uint64_t color_b_amp,
        uint64_t color_r_wavelength, uint64_t color_g_wavelength, uint64_t color_b_wavelength,
        uint64_t color_r_phase, uint64_t color_g_phase, uint64_t color_b_phase
    ) 
{ 
    if (calc_animation3_enable_debug)
        printf("I'm here and make you set x0--x8! %lu %lu %lu %lu %lu %lu %lu %lu %lu",
            color_r_amp, color_g_amp, color_b_amp,
            color_r_wavelength, color_g_wavelength, color_b_wavelength,
            color_r_phase, color_g_phase, color_b_phase
        );
}

// liest Daten aus einer Speicheradresse, und schiebt diese für den Aufruf in x1 ff. -- verändert diese danach aber nicht mehr und kehrt ohne Gelegenheit eines Segfaults sofort zurück.
void dump_animation
    (struct animation_definition* animation);
void dump_animation
    (struct animation_definition* animation)
{
    dump_animation_values(
        animation->color_r_amp, animation->color_g_amp, animation->color_b_amp,
        animation->color_r_wavelength, animation->color_g_wavelength, animation->color_b_wavelength, 
        animation->color_r_phase, animation->color_g_phase, animation->color_b_phase
    );
}








// =============================================================================
// FAKE EXTRA CODE


#include <assert.h>
// #include <complex.h>
#include <ctype.h>
// #include <errno.h>
// #include <fenv.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
// #include <locale.h>
// #include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

// #include <pta_benchmark.h>
// #include <pta_device.h>
// #include <pta_gprof.h>
// #include <pta_invoke_tests.h>
// #include <pta_secstor_ta_mgmt.h>
#include <pta_socket.h>
#include <pta_system.h>
#include <sdp_pta.h>
#include <tee_api.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
// #include <tee_arith_internal.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_isocket.h>
#include <tee_syscall_numbers.h>
#include <tee_ta_api.h>
#include <tee_tcpsocket.h>
#include <tee_udpsocket.h>
// #include <user_ta_header.h>
// #include <utee_defines.h>
// #include <utee_syscalls.h>
// #include <utee_types.h>

// #include <asm.S>
#include <atomic.h>
#include <bitstring.h>
// #include <compiler.h>
#include <mempool.h>
#include <printk.h>
// #include <speculation_barrier.h>
#include <string_ext.h>
#include <trace.h>
#include <trace_levels.h>
// #include <types_ext.h>
#include <util.h>

#include <mbedtls/aes.h>
#include <mbedtls/aesni.h>
#include <mbedtls/arc4.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/base64.h>
#include <mbedtls/bignum.h>
#include <mbedtls/blowfish.h>
#include <mbedtls/bn_mul.h>
#include <mbedtls/camellia.h>
#include <mbedtls/ccm.h>
#include <mbedtls/certs.h>
#include <mbedtls/check_config.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cipher_internal.h>
#include <mbedtls/cmac.h>
#include <mbedtls/compat-1.3.h>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/des.h>
#include <mbedtls/dhm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecjpake.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecp_internal.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/havege.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/md2.h>
#include <mbedtls/md4.h>
#include <mbedtls/md5.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/net.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/oid.h>
#include <mbedtls/padlock.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/pkcs11.h>
#include <mbedtls/pkcs12.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_time.h>
#include <mbedtls/ripemd160.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/ssl_internal.h>
#include <mbedtls/ssl_ticket.h>
#include <mbedtls/threading.h>
#include <mbedtls/timing.h>
#include <mbedtls/version.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/xtea.h>

#pragma GCC push_options
#pragma GCC optimize ("0")
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
// disable optimization to avoid GCC optimizing the references away.
static void includeLibs(void)
{
	void* ptr;
	// LIBUTILS
	// heap, from bget_malloc.o, see https://www.fourmilab.ch/bget/
	ptr = (void*) malloc;
	ptr = (void*) calloc;
	ptr = (void*) realloc;
	ptr = (void*) free;
	ptr = (void*) strdup;
	ptr = (void*) strndup;
	// memory analysis
	ptr = (void*) memchr;
	ptr = (void*) memcmp;
	// memory modification
	ptr = (void*) memcpy;
	ptr = (void*) memmove;
	ptr = (void*) memset;
	// string modification
	ptr = (void*) strcpy;
	ptr = (void*) strncpy;
	ptr = (void*) strlcpy;
	ptr = (void*) strlcat;
	// prints
	ptr = (void*) snprintf;
	ptr = (void*) snprintk;
	ptr = (void*) trace_printf;
	// string analysis
	ptr = (void*) strcmp;
	ptr = (void*) strncmp;
	ptr = (void*) strlen;
	ptr = (void*) strnlen;
	ptr = (void*) strchr;
	ptr = (void*) strstr;
	ptr = (void*) strrchr;
	// char analysis and modification
	// ptr = (void*) isupper;
	// ptr = (void*) isspace;
	// ptr = (void*) isalpha;
	// ptr = (void*) isdigit;
	// ptr = (void*) isxdigit;
	// ptr = (void*) tolower;
	// numbers
	ptr = (void*) strtoul;
	ptr = (void*) abs;
	// sorting
	ptr = (void*) qsort;
	ptr = (void*) buf_compare_ct;
	// atomic exchange
	ptr = (void*) atomic_inc32;
	ptr = (void*) atomic_dec32;
	// exception-like jumps
	ptr = (void*) setjmp;
	ptr = (void*) longjmp;
	// memorypools as faster heap alternative for bigints and such
	ptr = (void*) mempool_alloc;
	// no code: malloc_lock;
	// stack canary helper: stack_check
	
	// LIBUTEE
	assert(1); // probably is a macro, not a function. 
	ptr = (void*) abort;
	ptr = (void*) printf;
	// ptr = (void*) invoke_socket_pta;
	ptr = (void*) TEE_tcpSocket;
	ptr = (void*) TEE_GetPropertyAsBool;
	ptr = (void*) TEE_Panic;
	ptr = (void*) TEE_AllocateOperation;
	ptr = (void*) TEE_GetObjectInfo;
	ptr = (void*) TEE_BigIntConvertFromOctetString;
	ptr = (void*) TEE_BigIntInit;
	ptr = (void*) TEE_InvokeTACommand;
	
	// LIBMBEDTLS
	ptr = (void*) mbedtls_aes_init;
	// ptr = (void*) mbedtls_aesni_has_support;
	// ptr = (void*) mbedtls_arc4_init;
	ptr = (void*) mbedtls_asn1_get_len;
	ptr = (void*) mbedtls_asn1_write_len;
	ptr = (void*) mbedtls_base64_encode;
	// ptr = (void*) mbedtls_blowfish_init;
	ptr = (void*) mbedtls_mpi_init;
	// ptr = (void*) mbedtls_ccm_init;
	// ptr = (void*) mbedtls_camellia_init;
	// ptr = (void*) mbedtls_cipher_cmac_starts;
	ptr = (void*) mbedtls_cipher_list;
	ptr = (void*) mbedtls_ctr_drbg_init;
	ptr = (void*) mbedtls_entropy_init;
	ptr = (void*) mbedtls_ecp_point_init;
	// ptr = (void*) mbedtls_ecjpake_init;
	ptr = (void*) mbedtls_ecdh_init;
	// ptr = (void*) mbedtls_dhm_init;
	ptr = (void*) mbedtls_des_init;
	ptr = (void*) mbedtls_md5_init;
	// ptr = (void*) mbedtls_md4_init;
	// ptr = (void*) mbedtls_md2_init;
	ptr = (void*) mbedtls_md_init;
	// ptr = (void*) mbedtls_hmac_drbg_init;
	// ptr = (void*) mbedtls_havege_init;
	// ptr = (void*) mbedtls_gcm_init;
	// ptr = (void*) mbedtls_strerror;
	ptr = (void*) mbedtls_pem_init;
	// ptr = (void*) mbedtls_padlock_has_support;
	ptr = (void*) mbedtls_oid_get_numeric_string;
	// ptr = (void*) mbedtls_net_init;
	// ptr = (void*) mbedtls_memory_buffer_alloc_init;
	// ptr = (void*) mbedtls_pkcs5_pbes2;
	// ptr = (void*) mbedtls_pkcs11_init;
	ptr = (void*) mbedtls_pk_init;
	// ptr = (void*) mbedtls_pkcs12_pbe_sha1_rc4_128;
	// ptr = (void*) mbedtls_ripemd160_init;
	// ptr = (void*) mbedtls_platform_setup;
	// ptr = (void*) mbedtls_sha512_init;
	ptr = (void*) mbedtls_sha256_init;
	ptr = (void*) mbedtls_sha1_init;
	ptr = (void*) mbedtls_rsa_init;
	// ptr = (void*) mbedtls_ssl_init;
	ptr = (void*) mbedtls_x509_dn_gets;
	// ptr = (void*) mbedtls_xtea_setup;
	// ptr = (void*) mbedtls_version_check_feature;
	// ptr = (void*) mbedtls_platform_set_time;
	// ptr = (void*) mbedtls_set_alarm;
	// ptr = (void*) mbedtls_x509_crl_parse_der;
	ptr = (void*) mbedtls_x509_crt_parse_der;
	ptr = (void*) mbedtls_x509_csr_parse_der;
    ptr = ptr; // avoid Wunused-but-set-variable
}
#pragma GCC diagnostic pop
#pragma GCC pop_options
