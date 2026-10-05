#ifndef CME_ADMIN_H
#define CME_ADMIN_H
#include "common.h"
int cmeAdminCopy(sqlite3 *to, sqlite3 *from);
int cmeAdminKey(const char *path, char key[257]);
int cmeAdminSchema(sqlite3 *db);
int cmeAdminVerify(sqlite3 *db, const char *key, const char *profile);
int cmeAdminCompare(sqlite3 *before, sqlite3 *after);
int cmeAdminPlain(sqlite3 *db, const char *key, const char *profile);
int cmeAdminSave(sqlite3 *db, const char *directory, const char *name);
int cmeStorageMain(int argc, char **argv);
#endif
