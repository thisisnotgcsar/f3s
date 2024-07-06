#include <stdio.h>

void check3(char* arg) {
	char greeting[0x40];
	sprintf(greeting, "Greeting: %s", arg);
}

void check2(char* arg) {
	check3(arg);
}

void check1(char* arg) {
	check2(arg);
}

int main(int argc, char *argv[]) {
	check1(argv[1]);
	return 0;
}