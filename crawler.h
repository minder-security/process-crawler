#pragma once
#include <stdio.h>
#include <string.h>

#include "injector.h"

void inputHandler();
void printHelp();
int exitCleanup();

void inputHandler()
{
	char input_buf[0xff];	// Buffer for User Input

	while (1) {
		printf("Crawler>");
		fgets(input_buf, 0xfe, stdin);
		input_buf[strcspn(input_buf, "\n")] = 0x00;

		if (strlen(input_buf) == 0 || strspn(input_buf, " ") == strlen(input_buf)) continue;

		// Add new commands here
		else if (strcmp(input_buf, "help") == 0) {
			printHelp();
		}
		else if (strcmp(input_buf, "exit") == 0) {
			printf("Cleaning up... ");
			if (exitCleanup() == 0) printf("Done!");
			break;
		}

		// In case of command not recognized
		else {
			printf("Command '%s' not recognized, try command 'help' for more information.\n", input_buf);
		}
	}
}

void printHelp()
{
	printf("BASIC:\n\
			help\tprints this help message\n\
			exit\texits crawler and destroys all probes\n");
}

int exitCleanup()
{
	return 0;
}