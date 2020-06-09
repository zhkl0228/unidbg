#import "MobileCoreServices.h"
#import <stdio.h>

void _LSRegisterFilePropertyProvider() {
  if(is_debug()) {
    long lr = get_lr_reg();
    fprintf(stderr, "_LSRegisterFilePropertyProvider LR=%p\n", (void *) lr);
  }
}
