///////////////////////////////////////////////
///					SynaPS3lib 				///
///	          by n4ru && methionine_		///
/// 	Compatible with Sony PS3 SDK 3.41	///
///////////////////////////////////////////////
///					xmb.h					///
///			XMB related functions.			///
///////////////////////////////////////////////
#ifndef __XMB_H
#define __XMB_H

#include "system.h"

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

#endif /* __XMB_H */
