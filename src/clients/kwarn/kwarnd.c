/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * Usermode daemon which is responsible for sending kerberos credentials
 * expiration warnings to the user, syslog or snmp (eventually), depending
 * on how it is configured through /etc/krb5/warn.conf.
 * the code in this file was borrowed from gssd.c
 */

#pragma ident	"@(#)kwarnd.c	1.4	07/11/14 SMI"

#include <stdio.h>
#include <rpc/rpc.h>
#include <sys/syslog.h>
#include <sys/termios.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <stdlib.h>
#include <stropts.h>
#include <fcntl.h>
#include <strings.h>
#include <syslog.h>
#include <thread.h>
#include <netdb.h>
#include <libgen.h>
#include <signal.h>
#include <k5-platform.h>
#include "kwarnd.h"

#define	MAXTHREADS 64

int kwarnd_debug = 0;		/* enable debugging printfs */

extern void kwarnprog_1(struct svc_req *, register SVCXPRT *);
static void usage(void);
static void detachfromtty(void);
extern int svc_create_local_service(void (*) (),
					ulong_t, ulong_t, char *, char *);
extern void kwarnd_check_warning_list(void);
extern bool_t loadConfigFile(void);

/* following declarations needed in rpcgen-generated code */
int _rpcpmstart = 0;		/* Started by a port monitor ? */
int _rpcfdtype;			/* Whether Stream or Datagram ? */
int _rpcsvcdirty;		/* Still serving ? */

char myhostname[MAXHOSTNAMELEN] = {0};
char progname[MAXNAMELEN] = {0};

int
main(argc, argv)
int argc;
char **argv;
{
	register SVCXPRT *transp;
	extern int optind;
	int c;
	char mname[FMNAMESZ + 1];
	int rpc_svc_mode = RPC_SVC_MT_AUTO;
	extern int _getuid();


	/* set locale and domain for internationalization */
	setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	textdomain(TEXT_DOMAIN);

	(void) strlcpy(progname, basename(argv[0]), sizeof (progname));

	/*
	 * take special note that "_getuid()" is called here. This is necessary
	 * since we must fake out the mechanism libraries calls to getuid()
	 * with a special routine that is provided as part of kwarnd. However,
	 * the call below MUST call the real getuid() to ensure it is running
	 * as root.
	 */

#ifdef DEBUG
	(void) setuid(0);		/* DEBUG: set ruid to root */
#endif /* DEBUG */
	if (_getuid()) {
		(void) fprintf(stderr,
				_("[%s] must be run as root\n"), argv[0]);
#ifdef DEBUG
		(void) fprintf(stderr, _(" warning only\n"));
#else /* !DEBUG */
		exit(1);
#endif /* DEBUG */
	}

	while ((c = getopt(argc, argv, "d")) != -1)
		switch (c) {
		    case 'd':
			/* turn on debugging */
			kwarnd_debug = 1;
			break;
		    default:
			usage();
		}

	if (optind != argc) {
		usage();
	}

	(void) gethostname(myhostname, sizeof (myhostname));

	/*
	 * Started by inetd if name of module just below stream
	 * head is either a sockmod or timod.
	 */
	if (!ioctl(0, I_LOOK, mname) &&
		((strcmp(mname, "sockmod") == 0) ||
			(strcmp(mname, "timod") == 0))) {

		char *netid;
		struct netconfig *nconf;

		openlog("kwarnd", LOG_PID, LOG_DAEMON);

		if ((netid = getenv("NLSPROVIDER")) ==  NULL) {
			netid = "ticotsord";
		}

		if ((nconf = getnetconfigent(netid)) == NULL) {
			syslog(LOG_ERR, _("cannot get transport info"));
			exit(1);
		}

		if (strcmp(mname, "sockmod") == 0) {
			if (ioctl(0, I_POP, 0) || ioctl(0, I_PUSH, "timod")) {
				syslog(LOG_ERR,
					_("could not get the right module"));
				exit(1);
			}
		}

		/* XXX - is nconf even needed here? */
		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			syslog(LOG_ERR, _("cannot create server handle"));
			exit(1);
		}

		/*
		 * We use a NULL nconf because KWARNPROG has already been
		 * registered with rpcbind.
		 */
		if (!svc_reg(transp, KWARNPROG, KWARNVERS, kwarnprog_1, NULL)) {
			syslog(LOG_ERR,
			    _("unable to register (KWARNPROG, KWARNVERS)"));
			exit(1);
		}

		if (nconf)
			freenetconfigent(nconf);
	} else {

		if (!kwarnd_debug)
			detachfromtty();

		openlog("kwarnd", LOG_PID, LOG_DAEMON);

		if (svc_create_local_service(kwarnprog_1, KWARNPROG, KWARNVERS,
		    "netpath", "kwarnd") == 0) {
			syslog(LOG_ERR, _("unable to create service"));
			exit(1);
		}
	}


	if (kwarnd_debug) {
		fprintf(stderr, _("kwarnd start: \n"));
	}

	(void) signal(SIGCHLD, SIG_IGN);

	if (thr_create(NULL, 0,
			(void *(*)(void *))kwarnd_check_warning_list, NULL,
			THR_DETACHED | THR_DAEMON | THR_NEW_LWP,
			NULL)) {
		syslog(LOG_ERR, _("unable to create cache_cleanup thread"));
		exit(1);
	}

	if (!loadConfigFile()) {
		syslog(LOG_ERR, _("could not read config file\n"));
		exit(1);
	}

	if (!rpc_control(RPC_SVC_MTMODE_SET, &rpc_svc_mode)) {
		syslog(LOG_ERR, _("unable to set automatic MT mode"));
		exit(1);
	}

	svc_run();
	abort();
	/*NOTREACHED*/
#ifdef	lint
	return (1);
#endif
}

static void
usage(void)
{
	(void) fprintf(stderr, _("usage: %s [-d]\n"), progname);
	exit(1);
}


/*
 * detach from tty
 */
static void
detachfromtty(void)
{
	switch (fork()) {
	case -1:
		perror(_("kwarnd: can not fork"));
		exit(1);
		/*NOTREACHED*/
	case 0:
		break;
	default:
		exit(0);
	}

	/*
	 * Close existing file descriptors, open "/dev/null" as
	 * standard input, output, and error, and detach from
	 * controlling terminal.
	 */
	closefrom(0);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
	(void) setsid();
}

/*ARGSUSED*/
int
kwarnprog_1_freeresult(SVCXPRT *transport, xdrproc_t xdr_res, caddr_t res)
{
	xdr_free(xdr_res, res);
	return (1);
}
