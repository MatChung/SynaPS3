///////////////////////////////////////////////
///			SynaPS3lib 2011 (c) n4ru		///
///////////////////////////////////////////////
///					lv2.h					///
///		Functions using lv2 payloads.		///
///////////////////////////////////////////////
#ifndef __LV2_H
#define __LV2_H 

#include <cell/dbgfont.h> 
#include <cell/codec/pngdec.h> 

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


int getFW() {
	return syscall6(0x80000000002D7580ULL);
}

uint32_t Mount(char *old_path, char *new_path) {
	if(syscall35("/dev_hdd0", "/dev_hdd0") != 0x80010003) {
		syscall35(old_path, new_path);
	} else {
		if(sys8_enable(0) > 0) {									
			typedef struct										
			{
			path_open_entry entries[2];
			char arena[0x2000];
			} path_open_table;
			path_open_table open_table;
			uint64_t dest_table_addr;	
			sys8_path_table(0ULL);
			dest_table_addr= 0x80000000007FF000ULL-((sizeof(path_open_table)+15) & ~15);
			open_table.entries[0].compare_addr= ((uint64_t) &open_table.arena[0]) - ((uint64_t) &open_table) + dest_table_addr;
			open_table.entries[0].replace_addr= ((uint64_t) &open_table.arena[0x800])- ((uint64_t) &open_table) + dest_table_addr;
			open_table.entries[1].compare_addr= 0ULL;
			cellFsMkdir(new_path, CELL_FS_DEFAULT_CREATE_MODE_1);
			cellFsChmod(new_path, 0777);
			strncpy(&open_table.arena[0], old_path, 0x100);
			strncpy(&open_table.arena[0x800], new_path, 0x800);
			open_table.entries[0].compare_len= strlen(&open_table.arena[0]);
			open_table.entries[0].replace_len= strlen(&open_table.arena[0x800]);
			sys8_memcpy(dest_table_addr, (uint64_t) &open_table, sizeof(path_open_table));
			sys8_path_table( dest_table_addr);
		}
	}
	return 0;
}

void MountHome(char* fla) {
    struct stat stPath;
    if(stat(fla, &stPath) == 0) {
		Mount(fla, (char *) "/app_home/");
	}
}

void MountFlash(char* fla) {
    struct stat stPath;
    if(stat(fla, &stPath) == 0) {
		Mount(fla, (char *) "/dev_flash/");
	}
}

void MountBD(char *game_path) {	
		if(syscall35("/dev_hdd0", "/dev_hdd0") != 0x80010003) {
			syscall35("/dev_bdvd", game_path);
			syscall35("/app_home", game_path);
		} else {
			syscall36(game_path);
		}
}

unsigned char GetPayloadCaps() {
	unsigned char ret = 0;
    if(syscall35("/dev_hdd0", "/dev_hdd0") != 0x80010003) {
		ret |= PAYLOAD_CAPS_SYSCALL35;
    }
    if(sys8_enable(0) > 0) {
        ret |= PAYLOAD_CAPS_SYSCALL8;
    }
	if (strcmp(FirmwareVersion, "03.4100") == 0){
		uint64_t oldValue = syscall6(0x80000000000505d0ULL);
		syscall7(0x80000000000505d0ULL, 0xE92296887C0802A6ULL);
		if(syscall6(0x80000000000505d0ULL) == 0xE92296887C0802A6ULL) {
			syscall7(0x80000000000505d0ULL, oldValue);
			ret |= PAYLOAD_CAPS_PEEKPOKE;
		}
	} else {
		uint64_t oldValue = syscall6(0x80000000000505d0ULL);
		if(syscall6(0x80000000000505d0ULL) == oldValue) { 
			ret |= PAYLOAD_CAPS_PEEKPOKE;
		}
	}
	if(syscall36((char *) "/dev_bdvd") != (int) 0x80010003) {
		ret |= PAYLOAD_CAPS_SYSCALL36;
	}
    return ret;
}

void ControllerFix() {													
    if(sys8_enable(0) > 0) {											
        sys8_perm_mode(2);												
    } else {															
		if(syscall6(0x8000000000000000ULL) != 0x80010003) {				
			if (strcmp(FirmwareVersion, "03.4100")==0){					
				syscall7(0x80000000000505d0ULL, 0xE92296887C0802A6ULL); 	
			}
		}
	}
}

#endif /* __LV2_H */
