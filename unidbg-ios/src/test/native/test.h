#include <stdio.h>

typedef __uint64_t guardid_t;

/*
 * Guard types.
 *
 * GUARD_TYPE_FD: Guarded file descriptor.
 */
#define	GUARD_TYPE_FD		0x2

/*
 * File descriptor guard flavors.
 */

/* Forbid close(2), and the implicit close() that a dup2(2) may do.
 * Forces close-on-fork to be set immutably too.
 */
#define GUARD_CLOSE		(1u << 0)

/*
 * Forbid dup(2), dup2(2), and fcntl(2) subcodes F_DUPFD, F_DUPFD_CLOEXEC
 * on a guarded fd. Also forbids open's of a guarded fd via /dev/fd/
 * (an implicit dup.)
 */
#define GUARD_DUP		(1u << 1)

/*
 * Forbid sending a guarded fd via a socket
 */
#define GUARD_SOCKET_IPC	(1u << 2)

/*
 * Forbid creating a fileport from a guarded fd
 */
#define GUARD_FILEPORT		(1u << 3)

extern int guarded_kqueue_np(const guardid_t *guard, u_int guardflags);

static void hex(char *buf, void *ptr, size_t size) {
  const char *data = (const char *) ptr;
  int idx = 0;
  for(int i = 0; i < size; i++) {
    idx += sprintf(&buf[idx], "%02x", data[i] & 0xff);
  }
}
