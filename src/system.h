///////////////////////////////////////////////
///					system.h				///
///				Core functions.				///
///////////////////////////////////////////////
#ifndef __SYSTEM_H
#define __SYSTEM_H

#include <string.h> 
#include <unistd.h> 
#include <cell/cell_fs.h> 
#include "syscalls.h" 

#define STACK_1M	0x0000000000000070ULL
#define STACK_512K	0x0000000000000060ULL
#define STACK_256K	0x0000000000000050ULL
#define STACK_128K	0x0000000000000040ULL
#define STACK_96K	0x0000000000000030ULL
#define STACK_64K	0x0000000000000020ULL
#define STACK_32K	0x0000000000000010ULL

static char FirmwareVersion[10]="00.0000";

void exit() {
	sys_process_exit(1); 
}

char* versionTXT() {
  FILE *fp = fopen ("/dev_flash/vsh/etc/version.txt", "r" );  
  if ( fp != NULL )
  {	
    char line [ 16 ];
    if (fgets ( line, sizeof line, fp ) != NULL) {
      sprintf(FirmwareVersion, "%s", strstr(line, "release:")+8);
    } 
  } 
  return FirmwareVersion;
}

int getFW() {
	return syscall6(0x80000000002D7580ULL);
}

void BootGame(char eboot_path[256], bool highPriority, unsigned long long stackSize) {
    if (highPriority) {
        sys_game_process_exitspawn2(eboot_path, NULL, NULL, NULL, 0, 1001, stackSize);
    } else {
        sys_game_process_exitspawn2(eboot_path, NULL, NULL, NULL, 0, 3071, stackSize);
    }
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
			// syscall8 -> syscall35 conversion ends here
			return 8;
		}
	}
	return 0;
}

void MountHome(char *home_path) {
		if(syscall35("/dev_hdd0", "/dev_hdd0") != 0x80010003) {
			syscall35("/app_home", home_path);
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
			cellFsMkdir(home_path, CELL_FS_DEFAULT_CREATE_MODE_1);
			cellFsChmod(home_path, 0777);
			strncpy(&open_table.arena[0], "/app_home", 0x100);
			strncpy(&open_table.arena[0x800], home_path, 0x800);
			open_table.entries[0].compare_len= strlen(&open_table.arena[0]);
			open_table.entries[0].replace_len= strlen(&open_table.arena[0x800]);
			sys8_memcpy(dest_table_addr, (uint64_t) &open_table, sizeof(path_open_table));
			sys8_path_table( dest_table_addr);
			// syscall8 -> syscall35 conversion ends here
		}
	}
}

void MountFlash(char* fla) {
    struct stat stPath;
    if(stat(fla, &stPath) == 0) {
		Mount(fla, (char *) "/dev_flash/");
	}
}

void LoadIOFSModules() {
    cellSysmoduleLoadModule(CELL_SYSMODULE_IO);
    cellSysmoduleLoadModule(CELL_SYSMODULE_FS);
}

void UnloadIOFSModules() {
    cellSysmoduleUnloadModule(CELL_SYSMODULE_IO);
    cellSysmoduleUnloadModule(CELL_SYSMODULE_FS);
}

char LV2_Flash(bool flashStatus) {
	int openFlash;
	if(flashStatus) {
		openFlash = 1;
	} else {
		openFlash = 0;
	}
	return openFlash;
}

#endif /* __SYSTEM_H */
