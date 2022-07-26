#include <CoreFoundation/CoreFoundation.h>
#import "../frameworks.h"

#define errSecSuccess                                0;       /* No error. */
#define errSecUnimplemented                          -4;      /* Function or operation not implemented. */
#define errSecItemNotFound                           -25300;  /* The specified item could not be found in the keychain. */

const CFStringRef kSecClassGenericPassword = CFSTR("genp");
const CFStringRef kSecClass = CFSTR("class");
const CFStringRef kSecAttrService = CFSTR("svce");
const CFStringRef kSecAttrAccount = CFSTR("acct");
const CFStringRef kSecAttrAccessibleAlwaysThisDeviceOnly = CFSTR("dku");
const CFStringRef kSecAttrAccessible = CFSTR("pdmn");
const CFStringRef kSecReturnData = CFSTR("r_Data");
const CFStringRef kSecMatchLimitAll = CFSTR("m_LimitAll");
const CFStringRef kSecMatchLimitOne = CFSTR("m_LimitOne");
const CFStringRef kSecMatchLimit = CFSTR("m_Limit");
const CFStringRef kSecValueData = CFSTR("v_Data");
const CFStringRef kSecReturnAttributes = CFSTR("r_Attributes");
const CFStringRef kSecAttrAccessGroup = CFSTR("agrp");
const CFStringRef kSecAttrAccessibleAfterFirstUnlock = CFSTR("ck");
const CFStringRef kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = CFSTR("cku");
const CFStringRef kSecAttrGeneric = CFSTR("gena");
const CFStringRef kSecAttrLabel = CFSTR("labl");
const CFStringRef kSecAttrDescription = CFSTR("desc");
const CFStringRef kSecAttrSynchronizable = CFSTR("sync");
const CFStringRef kSecAttrAccessibleWhenUnlockedThisDeviceOnly = CFSTR("aku");
const CFStringRef kSecAttrSynchronizableAny = CFSTR("syna");
const CFStringRef kSecReturnPersistentRef = CFSTR("r_PersistentRef");

typedef struct SecRandom {
} *SecRandomRef;
const SecRandomRef kSecRandomDefault = NULL;

typedef uint8_t DERByte;
typedef size_t DERSize;

typedef struct {
	DERByte		*data;
	DERSize		length;
} DERItem;

typedef struct SecCertificate {
  CFRuntimeBase		_base;
  CFDataRef				data;
  DERItem				_der;			/* Entire certificate in DER form. */
} *SecCertificateRef;

SecCertificateRef SecCertificateCreateWithData(CFAllocatorRef allocator, CFDataRef data);
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
