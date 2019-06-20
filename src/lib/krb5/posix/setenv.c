/*
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdlib.h>
#include "pos-obsolete.h"

/*
 * MIT kerberos removed setenv.c with commit below:
 *	commit 6aa4f550d2492039911558075d0efe60de656bc6
 *	Author: Ken Raeburn <raeburn@mit.edu>
 *	Date:   Wed Aug 13 08:26:19 2003 +0000
 *
 *	* Makefile.in (OBJS, STLIBOBJS): Drop setenv.o.
 *	* setenv.c: Deleted.
 *	* pos-obsolete.h: Deleted.
 *
 *
 * We need to revive the file to retain compatibility for S10
 */

int
krb5_setenv(const char *name, const char *value, int rewrite)
{
	return (setenv(name, value, rewrite));
}

void
krb5_unsetenv(const char *name)
{
	unsetenv(name);
}

char *
krb5_getenv(const char *name)
{
	return (getenv(name));
}
