// INTENTIONALLY VULNERABLE CODE - FOR TESTING ONLY
// Buffer overflow and unsafe C code

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// VULNERABLE: strcpy without bounds checking
void vulnerable_copy_v1(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // Buffer overflow!
    printf("Buffer: %s\n", buffer);
}

// VULNERABLE: gets() function
void vulnerable_input() {
    char password[32];
    printf("Enter password: ");
    gets(password);  // Extremely dangerous!
}

// VULNERABLE: sprintf without bounds
void vulnerable_format(char *name) {
    char message[100];
    sprintf(message, "Hello, %s!", name);  // Can overflow
    printf("%s\n", message);
}

// VULNERABLE: strcat without bounds
void vulnerable_concat(char *str1, char *str2) {
    char result[50];
    strcpy(result, str1);
    strcat(result, str2);  // Overflow if combined length > 50
}

// VULNERABLE: Format string vulnerability
void vulnerable_printf(char *user_input) {
    printf(user_input);  // Should be printf("%s", user_input)
}

// VULNERABLE: Integer overflow in allocation
void vulnerable_malloc(int count) {
    int size = count * sizeof(int);  // Can overflow!
    int *array = malloc(size);
}

// VULNERABLE: system() with user input
void vulnerable_command(char *filename) {
    char cmd[256];
    sprintf(cmd, "cat %s", filename);
    system(cmd);  // Command injection
}

// SAFE EXAMPLES
void safe_copy(char *user_input) {
    char buffer[64];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}

void safe_input() {
    char password[32];
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
}

void safe_format(char *name) {
    char message[100];
    snprintf(message, sizeof(message), "Hello, %s!", name);
    printf("%s\n", message);
}

int main() {
    return 0;
}
