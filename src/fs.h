///////////////////////////////////////////////
///			SynaPS3lib 2011 (c) n4ru		///
///////////////////////////////////////////////
///					fs.h	 				///
///		Filesystem related functions.		///
///////////////////////////////////////////////
#ifndef __FS_H
#define __FS_H

#include <cell/cell_fs.h> 

char fsExist(char* filename) {
	CellFsStat sb;
	return cellFsStat(filename, &sb) == CELL_FS_SUCCEEDED;
}

bool fsMkdir(char* newDir) {
	if(fsStat(newDir)) {
		return 1;
	} else {
		cellFsMkdir(newDir, CELL_FS_DEFAULT_CREATE_MODE_1);
		return fsStat(newDir);
	}
}

bool fsRename(char* from, char* to) {
	if(!fsStat(to) && fsStat(from)) {
		cellFsRename(from, to);
		return fsStat(to);
	} else {
		return 1;
	}
}

bool fsMove(char* from, char* to) {
	if(!fsStat(to) && fsStat(from)) {
		// Move code here
		return fsStat(to);
	} else {
		return 1;
	}
}

#endif /* __FS_H */