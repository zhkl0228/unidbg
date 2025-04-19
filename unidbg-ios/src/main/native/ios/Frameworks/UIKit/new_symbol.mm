typedef unsigned long size_t;

void operator delete(void *ptr, size_t size) {
    operator delete(ptr);
}

void operator delete[](void *ptr, size_t size) {
    operator delete[](ptr);
}
