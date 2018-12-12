/* lib/rpc/xdr_alloc.c */
/*
 * Copyright (c) 2010, Oracle America, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the "Oracle America, Inc." nor the names of
 *       its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 */

#include <sys/types.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <inttypes.h>
#include "dyn.h"

static bool_t	xdralloc_putlong(XDR *, long *);
static bool_t	xdralloc_putbytes(XDR *, caddr_t, int);
static unsigned int	xdralloc_getpos(XDR *);
static rpc_inline_t *	xdralloc_inline(XDR *, int);
static void	xdralloc_destroy(XDR *);
static bool_t	xdralloc_putint32(XDR *, int32_t *);
static bool_t	xdralloc_notsup_getlong(XDR *, long *);
static bool_t	xdralloc_notsup_getbytes(XDR *, caddr_t, int);
static bool_t	xdralloc_notsup_setpos(XDR *, unsigned int);
static bool_t	xdralloc_notsup_getint32(XDR *, int32_t *);
static bool_t	xdralloc_notsup_control(XDR *, int, void *);
static struct	xdr_ops xdralloc_ops = {
     xdralloc_notsup_getlong,
     xdralloc_putlong,
     xdralloc_notsup_getbytes,
     xdralloc_putbytes,
     xdralloc_getpos,
     xdralloc_notsup_setpos,
     xdralloc_inline,
     xdralloc_destroy,
     xdralloc_notsup_control,
#if defined(_LP64)
     xdralloc_notsup_getint32,
     xdralloc_putint32,
#endif
};

/*
 * The procedure xdralloc_create initializes a stream descriptor for a
 * memory buffer.
 */
void xdralloc_create(XDR *xdrs, enum xdr_op op)
{
     xdrs->x_op = op;
     xdrs->x_ops = &xdralloc_ops;
     xdrs->x_private = (caddr_t) DynCreate(sizeof(char), -4);
     /* not allowed to fail */
}

caddr_t xdralloc_getdata(XDR *xdrs)
{
     return (caddr_t) DynGet((DynObject) xdrs->x_private, 0);
}

void xdralloc_release(XDR *xdrs)
{
     DynRelease((DynObject) xdrs->x_private);
}

static void xdralloc_destroy(XDR *xdrs)
{
     DynDestroy((DynObject) xdrs->x_private);
}

static bool_t xdralloc_notsup_getlong(
     XDR *xdrs,
     long *lp)
{
     return FALSE;
}

static bool_t xdralloc_putlong(
     XDR *xdrs,
     long *lp)
{
#if defined(_LP64)
     if ((*lp > INT32_MAX) || (*lp < INT32_MIN))
          return FALSE;
#endif

     int l = htonl((uint32_t) *lp);

     /* XXX assumes sizeof(int)==4 */
     if (DynInsert((DynObject) xdrs->x_private,
		   DynSize((DynObject) xdrs->x_private), &l,
		   sizeof(int)) != DYN_OK)
	  return FALSE;
     return (TRUE);
}

#if defined(_LP64)
static bool_t xdralloc_notsup_getint32(
     register XDR *xdrs,
     int32_t *lp)
{
     return FALSE;
}

static bool_t xdralloc_putint32(
     register XDR *xdrs,
     int32_t *lp)
{
     int l = htonl((uint32_t) *lp);

     /* XXX assumes sizeof(int)==4 */
     if (DynInsert((DynObject) xdrs->x_private,
		   DynSize((DynObject) xdrs->x_private), &l,
		   sizeof(int)) != DYN_OK)
	  return FALSE;
     return (TRUE);
}
#endif

static bool_t xdralloc_notsup_getbytes(
     XDR *xdrs,
     caddr_t addr,
     int len)
{
     return FALSE;
}


static bool_t xdralloc_putbytes(
     XDR *xdrs,
     caddr_t addr,
     int len)
{
     if (DynInsert((DynObject) xdrs->x_private,
		   DynSize((DynObject) xdrs->x_private),
		   addr, (int) len) != DYN_OK)
	  return FALSE;
     return TRUE;
}

static unsigned int xdralloc_getpos(XDR *xdrs)
{
     return DynSize((DynObject) xdrs->x_private);
}

static bool_t xdralloc_notsup_setpos(
     XDR *xdrs,
     unsigned int lp)
{
     return FALSE;
}



static rpc_inline_t *xdralloc_inline(
     XDR *xdrs,
     int len)
{
     return (rpc_inline_t *) 0;
}

static bool_t xdralloc_notsup_control(XDR *xdrs,
     int request,
     void *info)
{
     return FALSE;
}
