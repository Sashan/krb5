#!/bin/sh

#
# must relax warnings:
#	remove E_NO_IMPLICIT_DECL_ALLOWED (we need those to minimize
#		changes to kerberos client)
#
#	remove E_ATTRIBUTE_PARAM_UNDEFINED (not supported by compiler,
#		reduces noise)
#
WARN_CFLAGS="-errtags=yes -errwarn=E_BAD_PTR_INT_COMBINATION,E_BAD_PTR_INT_COMB_ARG,E_PTR_TO_VOID_IN_ARITHMETIC"	\
PATH=$PATH:/opt/SUNWspro/SOS8/bin/:/usr/ccs/bin/	\
#./configure 	--prefix=/builds1/anedvedi/krb5.upgrade/proto/root_i386/		\
#		--exec-prefix=/builds1/anedvedi/krb5.upgrade/proto/root_i386/		\
#		--datadir=/builds1/anedvedi/krb5.upgrade/proto/root_i386/		\
./configure	--mandir=/usr/man	\
		--bindir=/usr/bin	\
		--sbindir=/usr/sbin	\
		--libdir=/usr/lib	\
		--sysconfdir=/etc/krb5	\
		--localstatedir=/var	\
		--libexecdir=/usr/lib	\
		--libexecdir=/usr/lib/amd64	\
		--includedir=/usr/include/kerberosv5	\
		--with-tls-impl=openssl	\
		--with-crypto-impl=openssl	\
		--with-prng-alg=os	\
		--without-system-verto	\
#		--enable-pkinit	\

#		--with-ldap	\
#		--enable-audit-plugin=solaris # no auditing on S10


