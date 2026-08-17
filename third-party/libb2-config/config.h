/* Stand-in for the config.h that libb2's autotools build generates.
 *
 * blake2-impl.h includes "config.h" unconditionally, and blake2s-ref.c renames
 * its symbols through BLAKE2_IMPL_NAME(fun) == fun ## SUFFIX. We need exactly
 * two things from that header and nothing else, so we supply them here rather
 * than running autotools inside the submodule and dirtying it.
 *
 * This file is ours, not upstream's. The submodule stays pristine.
 */
#pragma once

/* Empty suffix: we want the plain names blake2s_init, blake2s_update, ... */
#define SUFFIX

/* Selects the memcpy load/store path instead of the byte-at-a-time one. Only
 * a performance choice — the portable path is used, and is correct, when the
 * compiler does not tell us the byte order. */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define NATIVE_LITTLE_ENDIAN 1
#endif
