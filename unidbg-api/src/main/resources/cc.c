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
