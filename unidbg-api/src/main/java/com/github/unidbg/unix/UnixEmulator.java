package com.github.unidbg.unix;

public interface UnixEmulator {

    int EPERM = 1; /* Operation not permitted */
    int ENOENT = 2; /* No such file or directory */
    int EBADF = 9; /* Bad file descriptor */
    int EAGAIN = 11; /* Resource temporarily unavailable */
    int ENOMEM = 12; /* Cannot allocate memory */
    int EACCES = 13; /* Permission denied */
    int EFAULT = 14; /* Bad address */
    int EEXIST = 17; /* File exists */
    int ENOTDIR = 20; /* Not a directory */
    int EINVAL = 22; /* Invalid argument */
    int ENOTTY = 25; /* Inappropriate ioctl for device */
    int ENOSYS = 38; /* Function not implemented */
    int ENOATTR = 93; /* Attribute not found */
    int EOPNOTSUPP = 95; /* Operation not supported on transport endpoint */
    int EAFNOSUPPORT = 97; /* Address family not supported by protocol family */
    int EADDRINUSE = 98; /* Address already in use */
    int ECONNREFUSED = 111; /* Connection refused */

}
