// Step 1: xcrun -sdk iphoneos clang -o cc $(ARCH_SPEC) cc.c
// Step 2: use ida F5 decompile for_patch function
// Step 3: Paste the F5 output and replace for_patch function
// Step 4: xcrun -sdk iphoneos clang -o cc $(ARCH_SPEC) cc.c -O3
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
