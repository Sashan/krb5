/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* clients/kdestroy/kdestroy.c - Destroy contents of credential cache */
/*
 * Copyright 1990 by the Massachusetts Institute of Technology.
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

/* Solaris Kerberos */
#include <rpc/types.h>
#include <rpc/rpcsys.h>
#include <rpc/rpcsec_gss.h>
#include <kerberosv5/private/ktwarn.h>

#include "k5-platform.h"
#include <krb5.h>
#include <com_err.h>
#include <locale.h>
#include <string.h>
#include <stdio.h>

#ifdef __STDC__
#define BELL_CHAR '\a'
#else
#define BELL_CHAR '\007'
#endif

extern int optind;
extern char *optarg;

/*
 * We add _rpcsys extern declariation because that ON build suppresses warning
 * of implicit declarition, while MIT kerberos build treats the warning
 * as an error.
 */
extern int _rpcsys(int, void *);

#ifndef _WIN32
#define GET_PROGNAME(x) (strrchr((x), '/') ? strrchr((x), '/') + 1 : (x))
#else
#define GET_PROGNAME(x) max(max(strrchr((x), '/'), strrchr((x), '\\')) + 1,(x))
#endif

char *progname;


static void
usage()
{
    fprintf(stderr, _("Usage: %s [-A] [-q] [-c cache_name]\n"), progname);
    fprintf(stderr, _("\t-A destroy all credential caches in collection\n"));
    fprintf(stderr, _("\t-q quiet mode\n"));
    fprintf(stderr, _("\t-c specify name of credentials cache\n"));
    exit(2);
}

/* Print a warning if there are still un-destroyed caches in the collection. */
static void
print_remaining_cc_warning(krb5_context context)
{
    krb5_error_code ret;
    krb5_ccache cache;
    krb5_cccol_cursor cursor;

    ret = krb5_cccol_cursor_new(context, &cursor);
    if (ret) {
        com_err(progname, ret, _("while listing credential caches"));
        exit(1);
    }

    ret = krb5_cccol_cursor_next(context, cursor, &cache);
    if (ret == 0 && cache != NULL) {
        fprintf(stderr,
                _("Other credential caches present, use -A to destroy all\n"));
        krb5_cc_close(context, cache);
    }

    krb5_cccol_cursor_free(context, &cursor);
}

int
main(int argc, char *argv[])
{
    krb5_context context;
    krb5_error_code ret;
    krb5_ccache cache = NULL;
    krb5_cccol_cursor cursor;
    char *cache_name = NULL;
    int code = 0, errflg = 0, quiet = 0, all = 0, c;

    /* Solaris Kerberos */
    krb5_principal me = NULL;
    char *client_name = NULL;
    struct krpc_revauth desarg;
    static  rpc_gss_OID_desc oid = {9, "\052\206\110\206\367\022\001\002\002"};
    static  rpc_gss_OID krb5_mech_type = &oid;

    setlocale(LC_ALL, "");
    progname = GET_PROGNAME(argv[0]);

    while ((c = getopt(argc, argv, "54Aqc:")) != -1) {
        switch (c) {
        case 'A':
            all = 1;
            break;
        case 'q':
            quiet = 1;
            break;
        case 'c':
            if (cache_name) {
                fprintf(stderr, _("Only one -c option allowed\n"));
                errflg++;
            } else {
                cache_name = optarg;
            }
            break;
        case '4':
            fprintf(stderr, _("Kerberos 4 is no longer supported\n"));
            exit(3);
            break;
        case '5':
            break;
        case '?':
        default:
            errflg++;
            break;
        }
    }

    if (optind != argc)
        errflg++;

    if (errflg)
        usage();

    ret = krb5_init_context(&context);
    if (ret) {
        com_err(progname, ret, _("while initializing krb5"));
        exit(1);
    }

    if (cache_name != NULL) {
        code = krb5_cc_set_default_name(context, cache_name);
        if (code) {
            com_err(progname, code, _("while setting default cache name"));
            exit(1);
        }
    }

    if (all) {
        code = krb5_cccol_cursor_new(context, &cursor);
        if (code) {
            com_err(progname, code, _("while listing credential caches"));
            exit(1);
        }
        while (krb5_cccol_cursor_next(context, cursor, &cache) == 0 &&
               cache != NULL) {
            code = krb5_cc_get_full_name(context, cache, &cache_name);
            if (code) {
                com_err(progname, code, _("composing ccache name"));
                exit(1);
            }
            code = krb5_cc_destroy(context, cache);
            if (code && code != KRB5_FCC_NOFILE) {
                com_err(progname, code, _("while destroying cache %s"),
                        cache_name);
            }
            krb5_free_string(context, cache_name);
        }
        krb5_cccol_cursor_free(context, &cursor);
        krb5_free_context(context);
        return 0;
    }

    /*
     *  Solaris Kerberos
     *  Let us destroy the kernel cache first.
     */
    desarg.version = 1;
    desarg.uid_1 = geteuid();
    desarg.rpcsec_flavor_1 = RPCSEC_GSS;
    desarg.flavor_data_1 = (void *) krb5_mech_type;
    code = _rpcsys(KRPC_REVAUTH, (void *)&desarg);
    if (code != 0) {
        fprintf(stderr, _("%s: kernel creds cache error %d \n"),
            progname, code);
    }

    code = krb5_cc_default(context, &cache);
    if (code) {
        com_err(progname, code, _("while resolving ccache"));
        exit(1);
    }

    /*
     * Solaris Kerberos
     * Get client name for ktkt_warnd(1M) msg.
     */
    code = krb5_cc_get_principal(context, cache, &me);
    if (code != 0)
        fprintf(stderr,
            _("%s: Could not obtain principal name from cache\n"),
                progname);
    else
         if ((code = krb5_unparse_name(context, me, &client_name)))
             fprintf(stderr,
                 _("%s: Could not unparse principal name found in cache\n"),
                     progname);

    code = krb5_cc_destroy(context, cache);
    if (code != 0) {
        com_err(progname, code, _("while destroying cache"));
        if (code != KRB5_FCC_NOFILE) {
            if (quiet) {
                fprintf(stderr, _("Ticket cache NOT destroyed!\n"));
            } else {
                fprintf(stderr, _("Ticket cache %cNOT%c destroyed!\n"),
                        BELL_CHAR, BELL_CHAR);
            }
            errflg = 1;
        }
    }

    if (!errflg) {
        if (!quiet)
            print_remaining_cc_warning(context);
        /* Solaris Kerberos - Delete ktkt_warnd(1M) entry. */
        if (client_name)
            kwarn_del_warning(client_name);
        else
            fprintf(stderr, _("%s: TGT expire warning NOT deleted\n"),
                progname);
    }

    /* Solaris Kerberos */
    krb5_free_unparsed_name(context, client_name);
    krb5_free_principal(context, me);
    krb5_free_context(context);
    return errflg;
}
