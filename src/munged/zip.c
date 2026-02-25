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
 *  Neither zlib nor bzlib encode the original uncompressed data length in
 *  their compressed output.
 *
 *  The compression functions prepend 8 bytes of metadata (zip_meta_t) to the
 *  compressed output for this purpose:
 *  - Bytes 0-3: sentinel value to validate metadata (big endian)
 *  - Bytes 4-7: original uncompressed data length (big endian)
 */


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define ZIP_MAGIC 0xCACACACA


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

/**
 *  Validate the compression type.
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


/**
 *  Compress data in a single pass using the specified compression method.
 *  The [vsrc] buffer of [isrclen] bytes is compressed into [vdst].
 *  On entry, [*idstlen] must contain the size of [vdst].
 *  On exit, [*idstlen] contains the size of compressed data.
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
zip_compress_block (munge_zip_t type,
                    void *vdst, int *idstlen, const void *vsrc, int isrclen)
{
    unsigned char *dst;
    unsigned long dstlen;
    unsigned char *src;
    unsigned long srclen;
    zip_meta_t *meta;

    if (zip_validate_type (type) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!vdst || !idstlen || *idstlen < 0 || !vsrc || isrclen < 0) {
        errno = EINVAL;
        return -1;
    }
    if (*idstlen < sizeof (zip_meta_t)) {
        errno = EMSGSIZE;
        return -1;
    }
    dst = (unsigned char *) vdst + sizeof (zip_meta_t);
    dstlen = (unsigned long) *idstlen - sizeof (zip_meta_t);
    src = (unsigned char *) vsrc;
    srclen = (unsigned long) isrclen;

    if (srclen == 0) {
        dstlen = 0;
    }
#if HAVE_PKG_BZLIB
    else if (type == MUNGE_ZIP_BZLIB) {
        unsigned int u = (unsigned int) dstlen;
        if (BZ2_bzBuffToBuffCompress ((char *) dst, &u, (char *) src,
                (unsigned int) srclen, 9, 0, 0) != BZ_OK) {
            errno = EIO;
            return -1;
        }
        dstlen = (unsigned long) u;
    }
#endif /* HAVE_PKG_BZLIB */
#if HAVE_PKG_ZLIB
    else if (type == MUNGE_ZIP_ZLIB) {
        if (compress (dst, &dstlen, src, srclen) != Z_OK) {
            errno = EIO;
            return -1;
        }
    }
#endif /* HAVE_PKG_ZLIB */
    else {
        /* failsafe since zip_validate_type() is checked above */
        errno = EINVAL;
        return -1;
    }
    dstlen += sizeof (zip_meta_t);
    if (dstlen > INT_MAX) {
        errno = ERANGE;
        return -1;
    }
    *idstlen = (int) dstlen;
    meta = (zip_meta_t *) vdst;
    meta->magic = htonl (ZIP_MAGIC);
    meta->length = htonl (srclen);
    return 0;
}


/**
 *  Decompress data in a single pass using the specified compression method.
 *  The [vsrc] buffer of [isrclen] bytes is decompressed into [vdst].
 *  On entry, [*idstlen] must contain the size of [vdst].
 *  On exit, [*idstlen] contains the size of decompressed data.
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
zip_decompress_block (munge_zip_t type,
                      void *vdst, int *idstlen, const void *vsrc, int isrclen)
{
    unsigned char *dst;
    unsigned long dstlen;
    unsigned char *src;
    unsigned long srclen;
    int n;

    if (zip_validate_type (type) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!vdst || !idstlen || *idstlen < 0 || !vsrc \
            || isrclen < sizeof (zip_meta_t)) {
        errno = EINVAL;
        return -1;
    }
    n = zip_decompress_length (type, vsrc, isrclen);
    if (n < 0) {
        /* errno already set */
        return -1;
    }
    if (*idstlen < n) {
        errno = EMSGSIZE;
        return -1;
    }
    dst = (unsigned char *) vdst;
    dstlen = (unsigned long) *idstlen;
    src = (unsigned char *) vsrc + sizeof (zip_meta_t);
    srclen = (unsigned long) isrclen - sizeof (zip_meta_t);

#if HAVE_PKG_BZLIB
    if (type == MUNGE_ZIP_BZLIB) {
        unsigned int u = (unsigned int) dstlen;
        if (BZ2_bzBuffToBuffDecompress ((char *) dst, &u, (char *) src,
                (unsigned int) srclen, 0, 0) != BZ_OK) {
            errno = EIO;
            return -1;
        }
        dstlen = (unsigned long) u;
    }
#endif /* HAVE_PKG_BZLIB */

#if HAVE_PKG_ZLIB
    if (type == MUNGE_ZIP_ZLIB) {
        if (uncompress (dst, &dstlen, src, srclen) != Z_OK) {
            errno = EIO;
            return -1;
        }
    }
#endif /* HAVE_PKG_ZLIB */

    if (dstlen > INT_MAX) {
        errno = ERANGE;
        return -1;
    }
    *idstlen = (int) dstlen;
    return 0;
}


/**
 *  Calculate the buffer size (in bytes) required for compressing [len] bytes
 *  using the specified compression method.  This is a worst-case estimate:
 *  - bzlib: 1% larger than input + 600 bytes
 *  - zlib:  0.1% larger than input + 12 bytes
 *  The calculation includes space for 8 bytes of metadata (magic + length).
 *  Return the required size, or -1 on error (with errno set).
 *
 *  Note: The [src] parameter is currently unused.
 */
int
zip_compress_length (munge_zip_t type, const void *src, int len)
{
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


/**
 *  Extract the decompressed (original) size from compressed data metadata.
 *  Return the decompressed size, or -1 on error (with errno set).
 *
 *  Note: The [type] parameter is currently unused.
 */
int
zip_decompress_length (munge_zip_t type, const void *src, int len)
{
    zip_meta_t *meta;
    uint32_t orig_len;

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
