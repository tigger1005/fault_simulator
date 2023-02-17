// Simple main program

int main(void) {
  volatile int count = 0;
  for (int i = 0; i < 1000; i++) {
    count += i;
  }
  return count;
}
