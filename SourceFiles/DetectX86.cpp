#if defined(__i386) || defined(__i386__) || defined(_M_IX86) || defined(__x86_64) || defined(__x86_64__) || defined(__amd64) || defined(_M_X64)
    #error ARCH_X86
#else
    #error ARCH_NON_X86
#endif
