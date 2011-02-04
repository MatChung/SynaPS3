///////////////////////////////////////////////
///			SynaPS3lib 2011 (c) n4ru		///
///////////////////////////////////////////////
///					backup.h				///
///		Functions specifically for backups.	///
///////////////////////////////////////////////
#ifndef __BACKUP_H
#define __BACKUP_H 

void launchBackup(char eboot_path[256], bool perm, bool mem) {
	if(!perm) {
		fsDel("/dev_hdd0/tmp/EBOOT.BIN");
		fsCopy(eboot_path, "/dev_hdd0/tmp/EBOOT.BIN");
		if (patchSELF("/dev_hdd0/tmp/EBOOT.BIN", "bdvd", "hdd0", 1, mem))
			launchSELF(eboot_path); // If there are no references to bdvd we can direct boot.
		else
			launchSELF("/dev_hdd0/tmp/EBOOT.BIN"); // If there are, we boot a patched version.
	} else {
		patchSELF(eboot_path);
	}
}

bool saveBackup(char game_path[256]) {
	fsCopy(game_path + "ICON0.PNG");
	fsCopy(game_path + "PIC2.PNG");
	fsCopy(game_path + "PIC1.PNG");
	fsCopy(game_path + "PIC0.PNG");
	fsCopy(game_path + "SND0.AT3");
	fsCopy(game_path + "PARAM.SFO)");
	fsCopy(game_path + "PIC2.PNG");
}

#endif /* __BACKUP_H */
