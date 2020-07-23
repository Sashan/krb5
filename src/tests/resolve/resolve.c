/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/resolve/resolve.c */
/*
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * A simple program to test the functionality of the resolver library.
 * It simply will try to get the IP address of the host, and then look
 * up the name from the address. If the resulting name does not contain the
 * domain name, then the resolve library is broken.
 *
 * Warning: It is possible to fool this program into thinking everything is
 * alright by a clever use of /etc/hosts - but this is better than nothing.
 *
 * Usage:
 *   resolve [hostname]
 *
 *   When invoked with no arguments, gethostname is used for the local host.
 *
 */

/* This program tests the resolve library and sees if it is broken... */

#include "k5-platform.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <netinet/in.h>
#include <netdb.h>

#include <sys/types.h>
#include <arpa/nameser.h>
#include <resolv.h>

int
resolve_dns(char *hostname)
{
    unsigned char answer[NS_MAXMSG], *ansp = NULL, *end;
    char name[NS_MAXDNAME];
    int anslen, len = 0, nq, na, hostlen, found = 0, type, class, ttl, size;
    struct __res_state stat;
    HEADER *h;

    (void) strncpy(name, hostname, NS_MAXDNAME);

    (void) memset(&stat, 0, sizeof (stat));
    if (res_ninit(&stat) == -1)
	return 1;
    anslen = sizeof (answer);

    len = res_nsearch(&stat, name, C_IN, T_A, answer, anslen);
    if (len < sizeof (HEADER)) {
	res_ndestroy(&stat);
	return 2;
    }

    ansp = answer;
    end = ansp + anslen;

    h = (HEADER *)answer;
    nq = ntohs(h->qdcount);
    na = ntohs(h->ancount);
    ansp += HFIXEDSZ;

    if (nq != 1 || na < 1) {
	res_ndestroy(&stat);
	return 3;
    }
    
    hostlen = sizeof (name);
    len = dn_expand(answer, end, ansp, name, hostlen);
    if (len < 0) {
	res_ndestroy(&stat);
	return 4;
    }

    ansp += len + QFIXEDSZ;

    if (ansp > end) {
	res_ndestroy(&stat);
	return 5;
    }

    while (na-- > 0 && ansp < end) {
	len = dn_expand(answer, end, ansp, name, hostlen);

	if (len < 0)
	    continue;

	ansp += len;			/* name */
	NS_GET16(type, ansp);		/* type */
	NS_GET16(class, ansp);		/* class */
	NS_GET32(ttl, ansp);		/* ttl */
	NS_GET16(size, ansp);		/* size */

	if ((ansp + size) > end) {
	    res_ndestroy(&stat);
	    return 6;
	}

	ansp += len;
	if (type == T_A && class == C_IN) {
	    found = 1;
	    break;
	}
    }

    if (found != 1) {
	res_ndestroy(&stat);
	return 7;
    }

    (void) printf("%s\n", name);
    res_ndestroy(&stat);

    return 0;
}

int
main(int argc, char **argv)
{
    struct addrinfo *ai = NULL, hint;
    char myname[MAXHOSTNAMELEN + 1], namebuf[NI_MAXHOST], abuf[256];
    const char *addrstr;
    int err, quiet = 0, dns = 0;
    char *ptr, *fqdn;

    argc--; argv++;
    while (argc) {
        if ((strcmp(*argv, "--quiet") == 0) ||
            (strcmp(*argv, "-q") == 0)) {
            quiet++;
        } else if (strcmp(*argv, "-d") == 0)
	    dns++;
	else
            break;
        argc--; argv++;
    }

    if (argc >= 1) {
        strlcpy(myname, *argv, sizeof(myname));
    } else {
        if(gethostname(myname, MAXHOSTNAMELEN)) {
            perror("gethostname failure");
            exit(1);
        }
    }

    myname[MAXHOSTNAMELEN] = '\0';  /* for safety */

    if (dns) {
	if (err = resolve_dns(myname)) {
	    fprintf(stderr,
		"Could not resolve hostname ('%s') through DNS - fatal: %d\n",
                myname, err);
	    exit(2);
	}
        exit(0);
    }

    /* Look up the address... */
    if (!quiet)
        printf("Hostname:  %s\n", myname);

    memset(&hint, 0, sizeof(hint));
    hint.ai_flags = AI_CANONNAME;
    err = getaddrinfo(myname, 0, &hint, &ai);
    if (err) {
        fprintf(stderr,
                "Could not look up address for hostname '%s' - fatal\n",
                myname);
        exit(2);
    }

    if (!quiet) {
        addrstr = inet_ntop(ai->ai_family, ai->ai_addr, abuf, sizeof(abuf));
        if (addrstr != NULL)
            printf("Host address: %s\n", addrstr);
    }

    err = getnameinfo(ai->ai_addr, ai->ai_addrlen, namebuf, sizeof(namebuf),
                      NULL, 0, NI_NAMEREQD);
    if (err && !quiet)
        fprintf(stderr, "Error looking up IP address\n");

    printf("%s%s\n", quiet ? "" : "FQDN: ", err ? ai->ai_canonname : namebuf);

    if (!quiet)
        printf("Resolve library appears to have passed the test\n");

    freeaddrinfo(ai);
    return 0;
}
