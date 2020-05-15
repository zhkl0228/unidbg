#include <CoreFoundation/CoreFoundation.h>

#define errSecSuccess                                0;       /* No error. */
#define errSecItemNotFound                           -25300;  /* The specified item could not be found in the keychain. */

const CFStringRef kSecClassGenericPassword = CFSTR("genp");
const CFStringRef kSecClass = CFSTR("class");
const CFStringRef kSecAttrService = CFSTR("svce");
const CFStringRef kSecAttrAccount = CFSTR("acct");
const CFStringRef kSecAttrAccessibleAlwaysThisDeviceOnly = CFSTR("dku");
const CFStringRef kSecAttrAccessible = CFSTR("pdmn");
const CFStringRef kSecReturnData = CFSTR("r_Data");
const CFStringRef kSecMatchLimitOne = CFSTR("m_LimitOne");
const CFStringRef kSecMatchLimit = CFSTR("m_Limit");
const CFStringRef kSecValueData = CFSTR("v_Data");
