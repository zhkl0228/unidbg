#import "../frameworks.h"
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>

enum CFURLRequestCachePolicy {

  /*
   * Allow the underlying protocol (like HTTP) to choose the most
   */
  kCFURLRequestCachePolicyProtocolDefault = 0,

  /*
   * Ignore any cached contents, requiring that the content come from
   * the origin server
   */
  kCFURLRequestCachePolicyReloadIgnoringCache = 1,

  /*
   * Return the contents of the cache (if any), otherwise load from the
   * origin server
   */
  kCFURLRequestCachePolicyReturnCacheDataElseLoad = 2,

  /*
   * Return the contents of the cache (if any), otherwise, return
   * nothing
   */
  kCFURLRequestCachePolicyReturnCacheDataDontLoad = 3
};
typedef enum CFURLRequestCachePolicy CFURLRequestCachePolicy;

typedef struct CFURLRequest {
    CFURLRef url;
    CFURLRequestCachePolicy   cachePolicy;
    CFStringRef			  httpMethod;
    CFMutableDictionaryRef headerFields;
    CFDictionaryRef		  multipleHeaderFields;
    CFDataRef				httpBody;
} *CFURLRequestRef;

typedef CFURLRequestRef CFMutableURLRequestRef;

CFDictionaryRef CFURLRequestCopyAllHTTPHeaderFields(CFURLRequestRef request);

CFStringRef CFURLRequestCopyHTTPHeaderFieldValue(
  CFURLRequestRef   request,
  CFStringRef	   headerField);

CFURLRef CFURLRequestGetURL(CFURLRequestRef request);

CFStringRef CFURLRequestCopyHTTPRequestMethod(CFURLRequestRef request);

void CFURLRequestSetHTTPHeaderFieldValue(
  CFMutableURLRequestRef   mutableHTTPRequest,
  CFStringRef			  httpHeaderField,
  CFStringRef			  httpHeaderFieldValue);

void CFURLRequestSetURL(
  CFMutableURLRequestRef   mutableRequest,
  CFURLRef				 url);

void CFURLRequestSetMultipleHTTPHeaderFields(
  CFMutableURLRequestRef   mutableHTTPRequest,
  CFDictionaryRef		  headerFields);

void CFURLRequestSetHTTPRequestMethod(
  CFMutableURLRequestRef   mutableHTTPRequest,
  CFStringRef			  httpMethod);

void CFURLRequestSetCachePolicy(
  CFMutableURLRequestRef	mutableRequest,
  CFURLRequestCachePolicy   cachePolicy);

CFMutableURLRequestRef CFURLRequestCreateMutable(
  CFAllocatorRef			alloc,
  CFURLRef				  URL,
  CFURLRequestCachePolicy   cachePolicy,
  CFTimeInterval			timeout,
  CFURLRef				  mainDocumentURL);

void CFURLRequestSetHTTPRequestBody(
  CFMutableURLRequestRef   mutableHTTPRequest,
  CFDataRef				httpBody);

CFDataRef CFURLRequestCopyHTTPRequestBody(CFURLRequestRef request);

void CFURLRequestSetTimeoutInterval(CFMutableURLRequestRef request, double timeoutInterval);
