///////////////////////////////////////////////
///					SynaPS3lib 				///
///	          by n4ru && methionine_		///
/// 	Compatible with Sony PS3 SDK 3.41	///
///////////////////////////////////////////////
///					syscalls.h				///
///				syscall functions.			///
///////////////////////////////////////////////

/*

syscall8
Copyright (c) 2010 Hermes <www.elotrolado.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are 
permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of 
  conditions and the following disclaimer. 
- Redistributions in binary form must reproduce the above copyright notice, this list 
  of conditions and the following disclaimer in the documentation and/or other 
  materials provided with the distribution. 
- The names of the contributors may not be used to endorse or promote products derived 
  from this software without specific prior written permission. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#ifndef __SYSCALLS_H
#define __SYSCALLS_H

#include <sys/spu_initialize.h> 
#include <sys/ppu_thread.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <stdarg.h> 
#include <stddef.h>
#include <assert.h> 
#include <string.h> 
#include <dirent.h> 
#include <unistd.h> 
#include <fcntl.h> 
#include <time.h> 
#include <math.h> 
#include <stddef.h> 
#include <sys/stat.h> 
#include <sys/process.h> 
#include <sys/memory.h> 
#include <sys/timer.h> 
#include <sys/return_code.h> 
#include <cell/gcm.h> 
#include <cell/pad.h> 
#include <cell/keyboard.h> 
#include <cell/sysmodule.h> 
#include <cell/dbgfont.h> 
#include <cell/codec/pngdec.h> 
#include <cell/cell_fs.h> 
#include <sysutil/sysutil_sysparam.h> 
#include <sysutil/sysutil_discgame.h> 
#include <sysutil/sysutil_msgdialog.h> 
#include <sysutil/sysutil_oskdialog.h> 
#include <iostream>
#include <fstream>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t out; 
	
typedef struct
{
	uint64_t compare_addr; // kernel address to compare string
	uint64_t replace_addr; // kernel address to replace string
	int compare_len;       // len of compare string
	int replace_len;       // len of replace string

} path_open_entry;

int sys8_disable(uint64_t key);

int sys8_enable(uint64_t key);

uint64_t sys8_memcpy(uint64_t dst, uint64_t src, uint64_t size);

uint64_t sys8_memset(uint64_t dst, uint64_t val, uint64_t size);

uint64_t  sys8_call(uint64_t addr, uint64_t param1, uint64_t param2);

uint64_t  sys8_alloc(uint64_t size, uint64_t pool);

uint64_t  sys8_free(uint64_t addr, uint64_t pool);

void sys8_panic(void);

int sys8_perm_mode(uint64_t mode);

uint64_t sys8_path_table(uint64_t addr_table);

#ifdef __cplusplus
  }
#endif

static uint64_t syscall8(register uint64_t cmd, register uint64_t param1, register  uint64_t param2, register  uint64_t param3) {
	__asm__  volatile ("li      11, 0x8\n\t"
					   "sc\n\t" : "=r" (cmd), "=r" (param1), "=r" (param2), "=r" (param3)
					   : "r" (cmd), "r" (param1), "r" (param2), "r" (param3)
					   : "%r0", "%r12", "%lr", "%ctr", "%xer", "%cr0", "%cr1", "%cr5", "%cr6", "%cr7", "memory");
	return cmd;
}

int sys8_disable(uint64_t key) {

	return (int) syscall8(0ULL, key, 0ULL, 0ULL);
}

int sys8_enable(uint64_t key) {

	return (int) syscall8(1ULL, key, 0ULL, 0ULL);
}

uint64_t sys8_memcpy(uint64_t dst, uint64_t src, uint64_t size) {

	return syscall8(2ULL, dst, src, size);

}

uint64_t sys8_memset(uint64_t dst, uint64_t val, uint64_t size) {

	return syscall8(3ULL, dst, val, size);

}

uint64_t sys8_call(uint64_t addr, uint64_t param1, uint64_t param2) {

	return syscall8(4ULL, addr, param1, param2);

}

uint64_t sys8_alloc(uint64_t size, uint64_t pool) {

	return syscall8(5ULL, size, pool, 0ULL);

}

uint64_t sys8_free(uint64_t addr, uint64_t pool) {

	return syscall8(6ULL, addr, pool, 0ULL);

}

void sys8_panic(void) {

	syscall8(7ULL, 0ULL, 0ULL, 0ULL);

}

int sys8_perm_mode(uint64_t mode) {

	return (int) syscall8(8ULL, mode, 0ULL, 0ULL);
}

uint64_t sys8_path_table(uint64_t addr_table) {

	return syscall8(9ULL, addr_table, 0ULL, 0ULL);
}

uint64_t syscall6(uint64_t addr) { 
	system_call_2(6, addr, out);
	return out; 
} 

void syscall7(uint64_t addr, uint64_t val) {
    system_call_2(7, addr, val); 
}

uint32_t syscall35(const char *old_path, const char *new_path) {			
	system_call_2(35, (uint32_t) old_path, (uint32_t) new_path);	
	return_to_user_prog(uint32_t);
	return 35;
}

int syscall36(char *game_path) {						
	system_call_1(36, (uint32_t) game_path);
	return 36;
}

#endif /* __SYSCALLS_H */
