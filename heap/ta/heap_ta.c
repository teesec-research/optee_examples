#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

// #include <utee_syscalls.h>
#include <heap_ta.h>
#include <string.h>
#include <util.h>
#include <stdlib.h>
#include <utee_syscalls.h>
// void utee_return(unsigned long ret) __noreturn;

// ================================================================
// TRACING
// ================================================================

#define SIGN() (IMSG("%s has been called, compiletime " __DATE__ " " __TIME__ "\n",__FUNCTION__))

// ================================================================
// DATA STRUCTURES AND BSS/DATA MEMORY
// ================================================================

char const * const SECRET = "TOPSECRETTOPSECRETTOPSECRET";

typedef struct User {
// There was a bug with the session management, thus we added a validity flag to avoid handling invalid entries:
bool isValid;
// The user who wants to authenticate later.
char* username;
// is set to true after the user has logged in
bool isLoggedIn;
size_t usernameLen;
// unicode passwords can contain null bytes, thus we have to save the length too. *cough* *cough*
size_t passwordLen;
// The password that the user has to pass later to succeed authentizing.
char* passwordFromDb;
} User;
const int const MAX_SESSION_COUNT = 4;
User *sessions[4] = {};

// ================================================================
// OPEN & CLOSE ENTRY POINTS
// ================================================================

TEE_Result TA_CreateEntryPoint(void)
{
    SIGN();
    
	DMSG("Hello, I'm HEAP!\n");
	DMSG("memcpy is at %p", (void*)memcpy);
	DMSG("sizeof(User) is 0x%zx", sizeof(User));
	DMSG("TA_OpenSessionEntryPoint is at %p", (void*)TA_OpenSessionEntryPoint);
	DMSG("TEE_InvokeTACommand is at %p", (void*)TEE_InvokeTACommand);
	DMSG("utee_log is at %p", (void*)utee_log);
	DMSG("utee_return is at %p", (void*)utee_return);
	DMSG("SECRET is at %p", (void*)SECRET);
	DMSG("TEE_ReadObjectData is at %p", (void*)TEE_ReadObjectData);
    
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    SIGN();
}

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


void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	SIGN();
}

// ================================================================
// HELPER FUNCTIONS
// ================================================================

void* memdup(const void* mem, size_t size);
void* memdup(const void* mem, size_t size)
{ 
   void* out = malloc(size);

   if(out != NULL)
       memcpy(out, mem, size);

   return out;
}

// ================================================================
// STUBS
// ================================================================

static char* aquirePasswordFromUsername(const char* username, size_t usernameLen, size_t *out_passwordLen)
{
    *out_passwordLen = 8;
    // query highly volatile database containing too short passwords using unescaped query string:
    return strdup("SQL:p4ssw0rd:FFFFFFFFFFFFFFFF")+4;
}

static void releasePassword(char* password)
{
    free(password-4);
}

// ================================================================
// COMMANDS
// ================================================================

static TEE_Result call_open_session(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES
        (
            TEE_PARAM_TYPE_MEMREF_INPUT, // username
            TEE_PARAM_TYPE_VALUE_OUTPUT, // session id 
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE 
        );

	SIGN();

	if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    // copy to avoid reading race conditions.
    size_t usernameLen = params[0].memref.size;
    char* username = memdup(params[0].memref.buffer,params[0].memref.size);
    if(!username)
        return TEE_ERROR_OUT_OF_MEMORY;
        
	// size_t size0 = reg_pair_to_64(params[1].value.a,params[1].value.b);
	// size_t size2 = params[2].memref.size;

    for ( size_t i = 0; i < MAX_SESSION_COUNT; i++)
    {
        // there is a memleak somewhere here, does anybody know how to valgrind a TA?
        if(sessions[i] == NULL || !sessions[i]->isValid)
        {
            User* user = calloc(sizeof(User),1);
            sessions[i] = user;
            user->isValid = true;
            user->username = username;
            user->usernameLen = usernameLen;
            user->isLoggedIn = false;
            user->passwordFromDb = aquirePasswordFromUsername(username,usernameLen,&user->passwordLen);
            // return id of session
            reg_pair_from_64(i,&params[1].value.a,&params[1].value.b);
            DMSG("Session %i created at %p.",(int)i, (void*) user);
            return TEE_SUCCESS; 
        }
    }
    
    // cleanup:
    
    free(username);
    
    DMSG("No free session.");
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result call_close_session(uint32_t param_types, TEE_Param params[4])
{   
	uint32_t exp_param_types = TEE_PARAM_TYPES
        (
            TEE_PARAM_TYPE_VALUE_INPUT, // session id 
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE 
        );

	SIGN();

	if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    size_t sessId = reg_pair_to_64(params[0].value.a,params[0].value.b);
    
    // we don't need to check for validity, the flag stays false.        
    if(sessions[sessId] == NULL || sessId >= MAX_SESSION_COUNT) // TODO remove second check for more freedom?
    {
        DMSG("Invalid Session ID");
        return TEE_ERROR_BAD_PARAMETERS;
    } 
        
    // COPYPASTE 100 TIMES:
    // I shall not free passwords in memory aquired from other modules, they said. Now it actually doesn't crash anymore.
    /* free(sessions[sessId]->passwordFromDb); */
    free(sessions[sessId]->username);
    
    // set the array entry to invalid to allow reusing the array memory
    sessions[sessId]->isValid = false;
    DMSG("Closed session.");
	return TEE_SUCCESS;
}

static TEE_Result call_tell_me(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES
        (
            TEE_PARAM_TYPE_VALUE_INPUT, // session id 
            TEE_PARAM_TYPE_MEMREF_OUTPUT, // SECRET. Iff logged in.
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE 
        );
	SIGN();

	if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
        
    
    size_t sessId = reg_pair_to_64(params[0].value.a,params[0].value.b);
    
    if(sessions[sessId] == NULL || sessId >= MAX_SESSION_COUNT || !sessions[sessId]->isValid || !sessions[sessId]->isLoggedIn) 
    {
        DMSG("Invalid Session ID");
        return TEE_ERROR_BAD_PARAMETERS;
    } 
        
    if (params[1].memref.size < strlen(SECRET)+1)
        return TEE_ERROR_OUT_OF_MEMORY; 
        
    memcpy(params[1].memref.buffer, SECRET, strlen(SECRET)+1);
    params[1].memref.size = strlen(SECRET)+1;
    DMSG("Told you so.");
    return TEE_SUCCESS;
}

static TEE_Result call_login(uint32_t param_types, TEE_Param params[4])
{
	
	uint32_t exp_param_types = TEE_PARAM_TYPES
        (
            TEE_PARAM_TYPE_VALUE_INPUT, // session id 
            TEE_PARAM_TYPE_MEMREF_INPUT, // SECRET. Iff logged in.
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE 
        );
	SIGN();

	if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
        
    
    size_t sessId = reg_pair_to_64(params[0].value.a,params[0].value.b);
    
    if(sessions[sessId] == NULL || sessId >= MAX_SESSION_COUNT || !sessions[sessId]->isValid) 
    {
        DMSG("Invalid Session ID");
        return TEE_ERROR_BAD_PARAMETERS;
    } 
    User *user = sessions[sessId];
    if(params[1].memref.size == user->passwordLen && memcmp(params[1].memref.buffer, user->passwordFromDb, user->passwordLen) == 0)
    {
        DMSG("Logged in!");
        user->isLoggedIn = true;
        return TEE_SUCCESS;
    }
    DMSG("Wrong p4ssw0rd!");
    return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result call_switch_user(uint32_t param_types, TEE_Param params[4])
{
	return TEE_ERROR_OUT_OF_MEMORY;
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
    
	switch (cmd_id)
	{
		case TA_HEAP_CMD_OPEN_SESSION:
			return call_open_session(param_types, params);
		case TA_HEAP_CMD_CLOSE_SESSION:
			return call_close_session(param_types, params);
		case TA_HEAP_CMD_LOGIN:
			return call_login(param_types, params);
		case TA_HEAP_CMD_TELL_ME:
			return call_tell_me(param_types, params);
		case TA_HEAP_CMD_SWITCH_USER:
			return call_switch_user(param_types, params);
			
		case TA_HEAP_CMD_PANIC:
			return *((TEE_Result*)NULL);
			
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}
