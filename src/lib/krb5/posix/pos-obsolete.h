/*
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _POS_OBSOLETE_H_
#define	_POS_OBSOLETE_H_
/*
 * These were used up until 1.2 release
 * however in.telnetd still uses them in S10.
 */
int krb5_setenv(const char *, const char *, int);
void krb5_unsetenv(const char *name);
char *krb5_getenv(const char *name);
#endif
