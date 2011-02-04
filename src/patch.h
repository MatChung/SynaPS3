///////////////////////////////////////////////
///			SynaPS3lib 2011 (c) n4ru		///
///////////////////////////////////////////////
///					patch.h					///
///			Game and system patches.		///
///////////////////////////////////////////////
#ifndef __PATCH_H
#define __PATCH_H 

bool patchSELF(char self_path[256], char* string1, char* string2, bool mem, bool file) {
	if(file) {
		fsDel("/dev_hdd0/tmp/tmp.elf");
		decryptSELF(self_path, "/dev_hdd0/tmp/tmp.elf");
		fsDel(self_path);
		if (!replaceString("/dev_hdd0/tmp/tmp.elf", string1, string2))
			encryptSELF("/dev_hdd0/tmp/tmp.elf", self_path);
			return 0;
		else
			return 1;
		fsDel("/dev_hdd0/tmp/tmp.elf");
	}
	if(mem) {
		// Patch string in memory
	}
}

#endif /* __PATCH_H */
