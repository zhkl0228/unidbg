#import <CydiaSubstrate/CydiaSubstrate.h>
#import <Fishhook/Fishhook.h>
#import "objc.h"

#include <stdio.h>
#include <pthread.h>
#include <dispatch/dispatch.h>

NSString *(*old_pathForResource)(id self, SEL _cmd, NSString *name, NSString *ext) = NULL;

NSString *new_pathForResource(id self, SEL _cmd, NSString *name, NSString *ext) {
  NSString *ret = old_pathForResource(self, _cmd, name, ext);
  NSLog(@"NSBundle pathForResource name=%@, ext=%@, ret=%@", name, ext, ret);
  return ret;
}

extern objc_msg_function old_objc_msgSend;
extern objc_msgSend_callback callback;

void hook_objc_msgSend(objc_msgSend_callback _callback) {
  callback = _callback;
  int ret = rebind_symbols((struct rebinding[1]){{"objc_msgSend", (void *)new_objc_msgSend, (void **)&old_objc_msgSend}}, 1);
  NSLog(@"hook_objc_msgSend callback=%p, ret=%d", callback, ret);
}

NSString *(*old_NSHomeDirectoryForUser)(NSString *userName);

NSString *new_NSHomeDirectoryForUser(NSString *userName) {
  NSString *ret = old_NSHomeDirectoryForUser(userName);
  NSLog(@"NSHomeDirectoryForUser userName=%@, ret=%@", userName, ret);
  return ret;
}

__attribute__((constructor))
void init() {
  NSLog(@"Initializing libhook");

  MSHookMessageEx([NSBundle class], @selector(pathForResource:ofType:), (IMP) &new_pathForResource, (IMP *) &old_pathForResource);
  MSHookFunction((void*)NSHomeDirectoryForUser,(void*)new_NSHomeDirectoryForUser, (void**)&old_NSHomeDirectoryForUser);

  NSLog(@"Initialized libhook");
}

bool _dispatch_runloop_root_queue_perform_4CF(dispatch_queue_t queue);

struct perform_state {
  dispatch_queue_t dq;
  pthread_cond_t cond;
  pthread_mutex_t lock;
  volatile bool finished;
};

static void *dispatch_queue_perform(void *arg) {
  struct perform_state *state = (struct perform_state *) arg;
  dispatch_queue_t dq = state->dq;

  while(_dispatch_runloop_root_queue_perform_4CF(dq)) {
  }

  state->finished = true;
  pthread_cond_broadcast(&state->cond);
  return NULL;
}

typedef bool (*t_dispatch)(dispatch_queue_t dq, void (^)(void));
static t_dispatch can_dispatch = NULL;

void (*old_dispatch_async)(dispatch_queue_t dq, void (^work)(void));
void new_dispatch_async(dispatch_queue_t dq, void (^work)(void)) {
  if(can_dispatch && !can_dispatch(dq, work)) {
    return;
  }

  dq = dispatch_queue_create(NULL, NULL);
  struct perform_state state;
  state.dq = dq;
  state.finished = false;
  pthread_cond_init(&state.cond, NULL);
  pthread_mutex_init(&state.lock, NULL);
  pthread_t thread = NULL;
  int ret = pthread_create(&thread, NULL, dispatch_queue_perform, &state);
  if(ret != 0) {
    printf("Patch dispatch_async dq=%p, ret=%d, thread=%p\n", dq, ret, thread);
  }
  old_dispatch_async(dq, work);
  while (!state.finished) {
    pthread_cond_wait(&state.cond, &state.lock);
  }

  pthread_cond_destroy(&state.cond);
  pthread_mutex_destroy(&state.lock);
  dispatch_release(dq);
}

void hook_dispatch_async(t_dispatch can_dispatch_f) {
  printf("Hook dispatch_async=%p, can_dispatch=%p.\n", &dispatch_async, can_dispatch_f);
  can_dispatch = can_dispatch_f;
  MSHookFunction((void*)&dispatch_async, (void*)new_dispatch_async, (void**)&old_dispatch_async);
}
