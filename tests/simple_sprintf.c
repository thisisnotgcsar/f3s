#include <stdio.h>

int main(int argc, char **argv) {
	char greeting[0x40];
	sprintf(greeting, argv[1]);
	return 0;
}