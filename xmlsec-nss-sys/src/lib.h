#define XMLSEC_CRYPTO_NSS
#define XMLSEC_NO_CRYPTO_DYNAMIC_LOADING
#define XMLSEC_NO_XSLT

#include <nss/cert.h>
#include <nss/pk11pub.h>

#include <xmlsec/templates.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>
