#include <stdio.h>

int main(int argc, char **argv) {
	char greeting[0x40];
	sprintf(greeting, "Greeting: %s", argv[1]);
}