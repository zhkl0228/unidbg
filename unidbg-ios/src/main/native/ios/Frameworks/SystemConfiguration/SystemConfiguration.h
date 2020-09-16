#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <CoreFoundation/CoreFoundation.h>
#import "../frameworks.h"

const CFStringRef kCNNetworkInfoKeySSID = CFSTR("SSID");
const CFStringRef kCNNetworkInfoKeyBSSID = CFSTR("BSSID");

CFStringRef SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address);

typedef enum SCNetworkReachabilityFlags : uint32_t {
  kSCNetworkReachabilityFlagsReachable = 1<<1,
  kSCNetworkReachabilityFlagsIsLocalAddress = 1<<16,
  kSCNetworkReachabilityFlagsIsWWAN = 1<<18,
} SCNetworkReachabilityFlags;

const SCNetworkReachabilityFlags defaultReachabilityFlags = kSCNetworkReachabilityFlagsReachable | kSCNetworkReachabilityFlagsIsLocalAddress | kSCNetworkReachabilityFlagsIsWWAN;

Boolean SCNetworkReachabilityGetFlags(void *target, SCNetworkReachabilityFlags *flags);

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

Boolean SCNetworkReachabilitySetCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityCallBack callback, SCNetworkReachabilityContext* context);

CFArrayRef CNCopySupportedInterfaces();

CFDictionaryRef CNCopyCurrentNetworkInfo(CFStringRef interfaceName);

Boolean SCNetworkReachabilityScheduleWithRunLoop(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode);

typedef void *SCDynamicStoreRef;

CFDictionaryRef SCDynamicStoreCopyProxies(SCDynamicStoreRef store);
