#import "CFNetwork.h"
#import <stdio.h>
#import <CoreFoundation/CoreFoundation.h>

CFDictionaryRef CFNetworkCopySystemProxySettings() {
  fprintf(stderr, "CFNetworkCopySystemProxySettings");
  return NULL;
}
