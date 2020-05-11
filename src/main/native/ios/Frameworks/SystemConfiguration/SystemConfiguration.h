#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <CoreFoundation/CoreFoundation.h>

const CFStringRef kCNNetworkInfoKeySSID = CFSTR("SSID");
const CFStringRef kCNNetworkInfoKeyBSSID = CFSTR("BSSID");

CFStringRef SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address) {
  fprintf(stderr, "SCNetworkReachabilityCreateWithAddress allocator=%p, address=%p\n", allocator, address);
  CFStringRef str = CFStringCreateWithCString(NULL, "SCNetworkReachabilityCreateWithAddress", kCFStringEncodingUTF8);
  return str;
}

typedef enum SCNetworkReachabilityFlags : uint32_t {
  kSCNetworkReachabilityFlagsReachable = 1<<1,
  kSCNetworkReachabilityFlagsIsLocalAddress = 1<<16,
  kSCNetworkReachabilityFlagsIsWWAN = 1<<18,
} SCNetworkReachabilityFlags;

Boolean SCNetworkReachabilityGetFlags(void *target, SCNetworkReachabilityFlags *flags) {
  *flags |= kSCNetworkReachabilityFlagsReachable;
  *flags |= kSCNetworkReachabilityFlagsIsLocalAddress;
  *flags |= kSCNetworkReachabilityFlagsIsWWAN;
  fprintf(stderr, "SCNetworkReachabilityGetFlags target=%p, flags=%p\n", target, flags);
  return TRUE;
}

typedef void *SCNetworkReachabilityRef;

/*!
	@typedef SCNetworkReachabilityCallBack
	@discussion Type of the callback function used when the
		reachability of a network address or name changes.
	@param target The SCNetworkReachability reference being monitored
		for changes.
	@param flags The new SCNetworkReachabilityFlags representing the
		reachability status of the network address/name.
	@param info A C pointer to a user-specified block of data.
 */
typedef void (*SCNetworkReachabilityCallBack)	(
						SCNetworkReachabilityRef	target,
						SCNetworkReachabilityFlags	flags,
						void				*info
						);

/*!
	@typedef SCNetworkReachabilityContext
	Structure containing user-specified data and callbacks for SCNetworkReachability.
	@field version The version number of the structure type being passed
		in as a parameter to the SCDynamicStore creation function.
		This structure is version 0.
	@field info A C pointer to a user-specified block of data.
	@field retain The callback used to add a retain for the info field.
		If this parameter is not a pointer to a function of the correct
		prototype, the behavior is undefined.  The value may be NULL.
	@field release The calllback used to remove a retain previously added
		for the info field.  If this parameter is not a pointer to a
		function of the correct prototype, the behavior is undefined.
		The value may be NULL.
	@field copyDescription The callback used to provide a description of
		the info field.
 */
typedef struct {
	CFIndex		version;
	void *		info;
	const void	*(*retain)(const void *info);
	void		(*release)(const void *info);
	CFStringRef	(*copyDescription)(const void *info);
} SCNetworkReachabilityContext;

Boolean SCNetworkReachabilitySetCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityCallBack callback, SCNetworkReachabilityContext* context) {
  fprintf(stderr, "SCNetworkReachabilitySetCallback target=%p, callback=%p, context=%p\n", target, callback, context);
  void *info = NULL;
  if(context) {
    info = context->info;
  }
  callback(target, kSCNetworkReachabilityFlagsReachable | kSCNetworkReachabilityFlagsIsWWAN, info);
  return TRUE;
}

CFArrayRef CNCopySupportedInterfaces() {
  CFStringRef array[] = { CFSTR("en0") };
  CFArrayRef arrayRef = CFArrayCreate(kCFAllocatorDefault, (void *)array, (CFIndex)1, NULL);
  fprintf(stderr, "CNCopySupportedInterfaces array=%p\n", arrayRef);
  return arrayRef;
}

CFDictionaryRef CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
  fprintf(stderr, "CNCopyCurrentNetworkInfo\n");
  CFStringRef keys[] = { kCNNetworkInfoKeySSID, kCNNetworkInfoKeyBSSID };
  CFStringRef values[] = { CFSTR("SSID"), CFSTR("00:00:00:00:00:01") };
  CFDictionaryRef dictionary = CFDictionaryCreate(kCFAllocatorDefault, (const void**) keys, (const void**) values, 2, NULL, NULL);
  return dictionary;
}

Boolean SCNetworkReachabilityScheduleWithRunLoop(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode) {
  fprintf(stderr, "SCNetworkReachabilityScheduleWithRunLoop target=%p\n", target);
  return TRUE;
}
