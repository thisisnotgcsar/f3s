#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	switch(atoi(argv[1])){
		case 0:
			puts("Nope");
			break;
		case 1:
			printf("%s\n", argv[1]);
			break;
		default:
			break;
	}
	return 0;
}