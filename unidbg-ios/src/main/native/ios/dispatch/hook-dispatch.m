#include <stdio.h>
#include <pthread.h>
#include <dispatch/dispatch.h>
#include <CydiaSubstrate/CydiaSubstrate.h>

bool _dispatch_runloop_root_queue_perform_4CF(dispatch_queue_t queue);

struct perform_state {
  dispatch_queue_t dq;
  pthread_cond_t cond;
  pthread_mutex_t lock;
  volatile bool finished;
};

#define DISPATCH_OBJECT_SUSPEND_INTERVAL 2

static void *main_queue_perform(void *arg) {
  dispatch_queue_t dq = dispatch_get_main_queue();
  while(true) {
    if(!_dispatch_runloop_root_queue_perform_4CF(dq)) {
      usleep(100);
    }
  }
}

static void *dispatch_queue_perform(void *arg) {
  struct perform_state *state = (struct perform_state *) arg;
  dispatch_queue_t dq = state->dq;
  int *ip = (int *) ((char *)dq + 0x30);
  int do_suspend_cnt = *ip;

  while(do_suspend_cnt != DISPATCH_OBJECT_SUSPEND_INTERVAL && _dispatch_runloop_root_queue_perform_4CF(dq)) {
  }

  state->finished = true;
  pthread_cond_broadcast(&state->cond);
  return NULL;
}

void (*old_dispatch_sync)(dispatch_queue_t dq, void (^work)(void));
void (*old_dispatch_async)(dispatch_queue_t dq, void (^work)(void));

void new_dispatch_sync(dispatch_queue_t dq, void (^work)(void)) {
  struct perform_state state;
  state.dq = dq;
  state.finished = false;
  pthread_cond_init(&state.cond, NULL);
  pthread_mutex_init(&state.lock, NULL);
  pthread_t thread = NULL;
  int ret = pthread_create(&thread, NULL, dispatch_queue_perform, &state);
  if(ret != 0) {
    printf("Patch dispatch_sync dq=%p, ret=%d, thread=%p\n", dq, ret, thread);
  }
  old_dispatch_async(dq, work);
  while (!state.finished) {
    pthread_cond_wait(&state.cond, &state.lock);
  }

  pthread_cond_destroy(&state.cond);
  pthread_mutex_destroy(&state.lock);
}

void new_dispatch_async(dispatch_queue_t dq, void (^work)(void)) {
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
}

__attribute__((constructor))
static void init() {
  pthread_t thread = NULL;
  int ret = pthread_create(&thread, NULL, main_queue_perform, NULL);
  printf("Patch dispatch: dispatch_sync=%p, dispatch_async=%p, ret=%d, thread=%p.\n", &dispatch_sync, &dispatch_async, ret, thread);
  MSHookFunction((void*)&dispatch_async, (void*)new_dispatch_async, (void**)&old_dispatch_async);
  // MSHookFunction((void*)&dispatch_sync, (void*)new_dispatch_sync, (void**)&old_dispatch_sync);
}
