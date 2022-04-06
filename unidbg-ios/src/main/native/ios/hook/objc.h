#import <Foundation/Foundation.h>
#import "../Frameworks/frameworks.h"

typedef id (*objc_msg_function)(id self, SEL _cmd, ...);

void new_objc_msgSend(id self, SEL _cmd);

uintptr_t pre_objc_msgSend(id self, SEL _cmd, ...);

typedef NSString *(*objc_msgSend_callback)(bool systemClass, const char *className, const char* cmd, uintptr_t lr);
