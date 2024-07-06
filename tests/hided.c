#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	char greeting[0x40];
	
	switch(atoi(argv[1])){
		case 0:
			puts("Nope");
			break;
		case 1:
			sprintf(greeting, "Greeting: %s", argv[1]);
			puts(greeting);
			break;
		default:
			break;
	}
}