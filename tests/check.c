#include <stdio.h>

void check(char* arg) {
	printf(arg);
}

int main(int argc, char *argv[]) {
	check(argv[1]);
	return 0;
}
