#define PERL_NO_GET_CONTEXT

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "src/sha3nist.c"
#include "src/jh.c"

typedef hashState *Digest__JH;

MODULE = Digest::JH    PACKAGE = Digest::JH

PROTOTYPES: ENABLE

SV *
jh_224 (...)
ALIAS:
    jh_224 = 224
    jh_256 = 256
    jh_384 = 384
    jh_512 = 512
PREINIT:
    hashState ctx;
    int i;
    unsigned char *data;
    unsigned char *result;
    STRLEN len;
CODE:
    if (Init(&ctx, ix) != SUCCESS)
        XSRETURN_UNDEF;
    for (i = 0; i < items; i++) {
        data = (unsigned char *)(SvPV(ST(i), len));
        if (Update(&ctx, data, len << 3) != SUCCESS)
            XSRETURN_UNDEF;
    }
    Newx(result, ix >> 3, unsigned char);
    if (Final(&ctx, result) != SUCCESS)
        XSRETURN_UNDEF;
    RETVAL = newSVpv(result, ix >> 3);
    Safefree(result);
OUTPUT:
    RETVAL

Digest::JH
new (class, hashsize)
    SV *class
    int hashsize
CODE:
    Newx(RETVAL, 1, hashState);
    if (Init(RETVAL, hashsize) != SUCCESS)
        XSRETURN_UNDEF;
OUTPUT:
    RETVAL

Digest::JH
clone (self)
    Digest::JH self
CODE:
    Newx(RETVAL, 1, hashState);
    Copy(self, RETVAL, 1, hashState);
OUTPUT:
    RETVAL

void
reset (self)
    Digest::JH self
PPCODE:
    if (Init(self, self->hashbitlen) != SUCCESS)
        XSRETURN_UNDEF;
    XSRETURN(1);

int
hashsize(self)
    Digest::JH self
ALIAS:
    algorithm = 1
CODE:
    RETVAL = self->hashbitlen;
OUTPUT:
    RETVAL

void
add (self, ...)
    Digest::JH self
PREINIT:
    int i;
    unsigned char *data;
    STRLEN len;
PPCODE:
    for (i = 1; i < items; i++) {
        data = (unsigned char *)(SvPV(ST(i), len));
        if (Update(self, data, len << 3) != SUCCESS)
            XSRETURN_UNDEF;
    }
    XSRETURN(1);

void
_add_bits (self, msg, bitlen)
    Digest::JH self
    SV *msg
    int bitlen
PREINIT:
    int i;
    unsigned char *data;
    STRLEN len;
PPCODE:
    if (! bitlen)
        XSRETURN(1);
    data = (unsigned char *)(SvPV(msg, len));
    if (bitlen > len << 3)
        bitlen = len << 3;
    if (Update(self, data, bitlen) != SUCCESS)
        XSRETURN_UNDEF;
    XSRETURN(1);

SV *
digest (self)
    Digest::JH self
PREINIT:
    unsigned char *result;
CODE:
    Newx(result, self->hashbitlen >> 3, unsigned char);
    if (Final(self, result) != SUCCESS)
        XSRETURN_UNDEF;
    RETVAL = newSVpv(result, self->hashbitlen >> 3);
    Safefree(result);
OUTPUT:
    RETVAL

void
DESTROY (self)
    Digest::JH self
CODE:
    Safefree(self);
