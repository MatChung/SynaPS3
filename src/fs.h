///////////////////////////////////////////////
///					fs.h	 				///
///		Filesystem related functions.		///
///////////////////////////////////////////////
#ifndef __FS_H
#define __FS_H

#include <cell/cell_fs.h> 

char fsStat(char* filename) {
	CellFsStat sb;
	return cellFsStat(filename, &sb) == CELL_FS_SUCCEEDED;
}

bool fsMkdir(char* newDir) {
	if(fsStat(newDir)) {
		return false;
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

#endif /* __FS_H */