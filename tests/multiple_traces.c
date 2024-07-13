#include <stdio.h>

void check1(char* arg) {
	printf(arg);
}

void check2(char* arg) {
	printf(arg);
}

int main(int argc, char *argv[]) {
	if(*argv[1] == 1)
		check1(argv[1]);
	else
		check2(argv[1]);
	return 0;
}