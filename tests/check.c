#include <stdio.h>

void check(char* arg) {
	char greeting[0x40];
	sprintf(greeting, "Greeting: %s", arg);
}

int main(int argc, char *argv[]) {
	check(argv[1]);
	return 0;
}
