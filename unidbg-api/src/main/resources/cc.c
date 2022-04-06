#include <stdio.h>
#define _BYTE char
#define __int16 short
#define __int64 long
#define _QWORD long
#define HIWORD(l) ((unsigned int)((l)>>48) & 0xffffULL)
#define LODWORD(l) ((unsigned int)(l) & 0xffffffffULL)
#define HIDWORD(l) ((unsigned int)((l)>>32) & 0xffffffffULL)
#define __fastcall
static inline unsigned long __ROR8__(unsigned long val, int rot) {
	return (val >> rot) | (val << (64 - rot));
}
// Step 1: xcrun -sdk iphoneos clang -o cc cc.c $(ARCH_SPEC)
// Step 2: use ida F5 decompile for_patch function
// Step 3: Paste the F5 output and replace for_patch function
// Step 4: xcrun -sdk iphoneos clang -o cc cc.c -O3 $(ARCH_SPEC)
__attribute__((naked))
void for_patch() {
  __asm__ volatile(
$(REPLACE_ASM)
  );
}
int main(int argc, char* argv[]) {
  for_patch();
  return 0;
}
