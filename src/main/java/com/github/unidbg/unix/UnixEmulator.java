package com.github.unidbg.unix;

import com.github.unidbg.Emulator;

public interface UnixEmulator extends Emulator {

    int EPERM = 1; /* Operation not permitted */
    int EBADF = 9; /* Bad file descriptor */
    int EAGAIN = 11; /* Resource temporarily unavailable */
    int ENOMEM = 12; /* Cannot allocate memory */
    int EACCES = 13; /* Permission denied */
    int EFAULT = 14; /* Bad address */
    int ENOTDIR = 20; /* Not a directory */
    int EINVAL = 22; /* Invalid argument */
    int ENOTTY = 25; /* Inappropriate ioctl for device */
    int ENOSYS = 38; /* Function not implemented */
    int EAFNOSUPPORT = 97; /* Address family not supported by protocol family */
    int ECONNREFUSED = 111; /* Connection refused */

}
