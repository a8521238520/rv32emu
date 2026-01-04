#include "dtc/libfdt/libfdt.h"

__attribute__((weak)) const char *fdt_strerror(int err)
{
    switch (err) {
    case FDT_ERR_NOTFOUND:
        return "not found";
    case FDT_ERR_EXISTS:
        return "exists";
    case FDT_ERR_NOSPACE:
        return "no space";
    case FDT_ERR_BADOFFSET:
        return "bad offset";
    case FDT_ERR_BADPATH:
        return "bad path";
    case FDT_ERR_BADPHANDLE:
        return "bad phandle";
    case FDT_ERR_BADSTATE:
        return "bad state";
    case FDT_ERR_TRUNCATED:
        return "truncated";
    case FDT_ERR_BADMAGIC:
        return "bad magic";
    case FDT_ERR_BADVERSION:
        return "bad version";
    case FDT_ERR_BADSTRUCTURE:
        return "bad structure";
    case FDT_ERR_BADLAYOUT:
        return "bad layout";
    case FDT_ERR_INTERNAL:
        return "internal";
    case FDT_ERR_BADNCELLS:
        return "bad number of cells";
    case FDT_ERR_BADVALUE:
        return "bad value";
    case FDT_ERR_BADOVERLAY:
        return "bad overlay";
    case FDT_ERR_NOPHANDLES:
        return "no phandles";
    case FDT_ERR_BADFLAGS:
        return "bad flags";
    default:
        return "unknown";
    }
}
