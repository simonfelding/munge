/*****************************************************************************
 *  Copyright (C) 2007-2026 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://github.com/dun/munge>.
 *
 *  MUNGE is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free
 *  Software Foundation, either version 3 of the License, or (at your option)
 *  any later version.  Additionally for the MUNGE library (libmunge), you
 *  can redistribute it and/or modify it under the terms of the GNU Lesser
 *  General Public License as published by the Free Software Foundation,
 *  either version 3 of the License, or (at your option) any later version.
 *
 *  MUNGE is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  and GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  and GNU Lesser General Public License along with MUNGE.  If not, see
 *  <https://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#if HAVE_BZLIB_H
#  include <stdio.h>                    /* for Solaris */
#  include <bzlib.h>
#endif /* HAVE_BZLIB_H */

#if HAVE_ZLIB_H
#  include <zlib.h>
#endif /* HAVE_ZLIB_H */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <string.h>
#include <munge.h>
#include "common.h"
#include "zip.h"


/*****************************************************************************
 *  Notes
 *****************************************************************************/
/*
 *  Neither the zlib nor bzlib compression routines encode the original length
 *    of the uncompressed data in the compressed output.
 *  The following "zip" routines allocate an additional 8 bytes of metadata
 *    (zip_meta_t) that is prepended to the compressed output for this purpose.
 *    The first 4 bytes contain a sentinel to check if the metadata is valid.
 *    The next 4 bytes contain the original length of the uncompressed data.
 *    Both values are in MSBF (ie, big endian) format.
 */


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define ZIP_MAGIC                       0xCACACACA


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef struct {
    uint32_t magic;
    uint32_t length;
} zip_meta_t;


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  Validate the compression type.
 *  Return 0 if valid, or -1 if invalid (with errno set).
 */
int
zip_validate_type (munge_zip_t type)
{
#if HAVE_PKG_BZLIB
    if (type == MUNGE_ZIP_BZLIB) {
        return 0;
    }
#endif /* HAVE_PKG_BZLIB */

#if HAVE_PKG_ZLIB
    if (type == MUNGE_ZIP_ZLIB) {
        return 0;
    }
#endif /* HAVE_PKG_ZLIB */

    errno = EINVAL;
    return -1;
}


/*  Compresses the [src] buffer of length [srclen] in a single pass using the
 *    compression method [type].  The resulting compressed output is stored
 *    in the [dst] buffer.
 *  Upon entry, [*pdstlen] must be set to the size of the [dst] buffer.
 *  Upon exit, [*pdstlen] is set to the size of the compressed data.
 *  Returns 0 on success, or -1 or error.
 */
int
zip_compress_block (munge_zip_t type,
                    void *dst, int *pdstlen, const void *src, int srclen)
{
    unsigned char *xdst;
    unsigned int   xdstlen;
    unsigned char *xsrc;
    unsigned int   xsrclen;
    zip_meta_t    *pmeta;

    if (zip_validate_type (type) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!dst || !pdstlen || *pdstlen < 0 || !src || srclen < 0) {
        errno = EINVAL;
        return -1;
    }
    if (*pdstlen < sizeof (zip_meta_t)) {
        errno = EMSGSIZE;
        return -1;
    }
    xdst = (unsigned char *) dst + sizeof (zip_meta_t);
    xdstlen = *pdstlen - sizeof (zip_meta_t);
    xsrc = (unsigned char *) src;
    xsrclen = srclen;

    if (xsrclen == 0) {
        xdstlen = 0;
    }
#if HAVE_PKG_BZLIB
    else if (type == MUNGE_ZIP_BZLIB) {
        if (BZ2_bzBuffToBuffCompress ((char *) xdst, &xdstlen,
                (char *) xsrc, xsrclen, 9, 0, 0) != BZ_OK) {
            errno = EIO;
            return -1;
        }
    }
#endif /* HAVE_PKG_BZLIB */
#if HAVE_PKG_ZLIB
    /*
     *  XXX: The use of the "xdstlen_ul" temporary variable is to avoid the
     *       gcc3.3 compiler warning: "dereferencing type-punned pointer
     *       will break strict-aliasing rules".  A mere cast doesn't suffice.
     */
    else if (type == MUNGE_ZIP_ZLIB) {
        unsigned long xdstlen_ul = xdstlen;
        if (compress (xdst, &xdstlen_ul,
                xsrc, (unsigned long) xsrclen) != Z_OK) {
            errno = EIO;
            return -1;
        }
        xdstlen = xdstlen_ul;
    }
#endif /* HAVE_PKG_ZLIB */
    else {
        /* failsafe since zip_validate_type() is checked above */
        errno = EINVAL;
        return -1;
    }
    xdstlen += sizeof (zip_meta_t);
    if (xdstlen > INT_MAX) {
        errno = ERANGE;
        return -1;
    }
    *pdstlen = (int) xdstlen;
    pmeta = dst;
    pmeta->magic = htonl (ZIP_MAGIC);
    pmeta->length = htonl (xsrclen);
    return 0;
}


/*  Decompresses the [src] buffer of length [srclen] in a single pass using the
 *    compression method [type].  The resulting decompressed (original) output
 *    is stored in the [dst] buffer.
 *  Upon entry, [*pdstlen] must be set to the size of the [dst] buffer.
 *  Upon exit, [*pdstlen] is set to the size of the decompressed data.
 *  Returns 0 on success, or -1 or error.
 */
int
zip_decompress_block (munge_zip_t type,
                      void *dst, int *pdstlen, const void *src, int srclen)
{
    unsigned char *xdst;
    unsigned int   xdstlen;
    unsigned char *xsrc;
    unsigned int   xsrclen;
    int            n;

    if (zip_validate_type (type) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!dst || !pdstlen || *pdstlen < 0 || !src \
            || srclen < sizeof (zip_meta_t)) {
        errno = EINVAL;
        return -1;
    }
    n = zip_decompress_length (type, src, srclen);
    if (n < 0) {
        /* errno already set */
        return -1;
    }
    if (*pdstlen < n) {
        errno = EMSGSIZE;
        return -1;
    }
    xdst = dst;
    xdstlen = *pdstlen;
    xsrc = (unsigned char *) src + sizeof (zip_meta_t);
    xsrclen = srclen - sizeof (zip_meta_t);

#if HAVE_PKG_BZLIB
    if (type == MUNGE_ZIP_BZLIB) {
        if (BZ2_bzBuffToBuffDecompress ((char *) xdst, &xdstlen,
                (char *) xsrc, xsrclen, 0, 0) != BZ_OK) {
            errno = EIO;
            return -1;
        }
    }
#endif /* HAVE_PKG_BZLIB */

#if HAVE_PKG_ZLIB
    /*
     *  XXX: The use of the "xdstlen_ul" temporary variable is to avoid the
     *       gcc3.3 compiler warning: "dereferencing type-punned pointer
     *       will break strict-aliasing rules".  A mere cast doesn't suffice.
     */
    if (type == MUNGE_ZIP_ZLIB) {
        unsigned long xdstlen_ul = xdstlen;
        if (uncompress (xdst, &xdstlen_ul,
                xsrc, (unsigned long) xsrclen) != Z_OK) {
            errno = EIO;
            return -1;
        }
        xdstlen = xdstlen_ul;
    }
#endif /* HAVE_PKG_ZLIB */

    if (xdstlen > INT_MAX) {
        errno = ERANGE;
        return -1;
    }
    *pdstlen = (int) xdstlen;
    return 0;
}


/*  Returns a worst-case estimate for the buffer length needed to compress data
 *    in the [src] buffer of length [len] using the compression method [type],
 *    or -1 on error.
 */
int
zip_compress_length (munge_zip_t type, const void *src, int len)
{
/*  For zlib "deflate" compression, allocate an output buffer at least 0.1%
 *    larger than the uncompressed input, plus an additional 12 bytes.
 *  For bzlib compression, allocate an output buffer at least 1% larger than
 *    the uncompressed input, plus an additional 600 bytes.
 *  Also reserve space for encoding the size of the uncompressed data.
 *  The "+1" is for the double-to-int conversion to perform a ceiling function.
 *
 *  XXX: Note the [src] parm is not currently used here.
 */
    double result;

    if (!src || len < 0) {
        errno = EINVAL;
        return -1;
    }
    if (len == 0) {
        return sizeof (zip_meta_t);
    }
#if HAVE_PKG_BZLIB
    if (type == MUNGE_ZIP_BZLIB) {
        result = (len * 1.01) + 600 + 1 + sizeof (zip_meta_t);
        if (result > INT_MAX) {
            errno = ERANGE;
            return -1;
        }
        return (int) result;
    }
#endif /* HAVE_PKG_BZLIB */

#if HAVE_PKG_ZLIB
    if (type == MUNGE_ZIP_ZLIB) {
        result = (len * 1.001) + 12 + 1 + sizeof (zip_meta_t);
        if (result > INT_MAX) {
            errno = ERANGE;
            return -1;
        }
        return (int) result;
    }
#endif /* HAVE_PKG_ZLIB */

    errno = EINVAL;
    return -1;
}


/*  Returns the decompressed (original) length of the compressed data
 *    in the [src] buffer of length [len], or -1 on error.
 */
int
zip_decompress_length (munge_zip_t type, const void *src, int len)
{
/*  XXX: Note the [type] parm is not currently used here.
 */
    zip_meta_t    *meta;
    uint32_t       orig_len;

    if (!src) {
        errno = EINVAL;
        return -1;
    }
    if (len < sizeof (zip_meta_t)) {
        errno = EINVAL;
        return -1;
    }
    meta = (void *) src;
    if (ntohl (meta->magic) != ZIP_MAGIC) {
        errno = EBADMSG;
        return -1;
    }
    orig_len = ntohl (meta->length);
    if (orig_len > INT_MAX) {
        errno = ERANGE;
        return -1;
    }
    return (int) orig_len;
}
