#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INSTRUCTION_LENGTH 100
#define NUM_REGISTERS 10

int registers[NUM_REGISTERS];
int number[2];

typedef struct {
    char instruction[MAX_INSTRUCTION_LENGTH];
} Instruction;

void executeInstructions(const char *filePath);
void parseAndExecuteInstruction(const char *instruction, int *currentIndex, int numInstructions);
int parseOperand(const char *operand, int *isRegister, int *value, int i);
void add(int operand1, int isRegister1, int operand2, int isRegister2);
void subtract(int operand1, int isRegister1, int operand2, int isRegister2);
void multiply(int operand1, int isRegister1, int operand2, int isRegister2);
void divide(int operand1, int isRegister1, int operand2, int isRegister2);
void move(int operand1, int isRegister1, int operand2, int isRegister2);
void compare(int operand1, int isRegister1, int operand2, int isRegister2);
void jump(int lineNumber, int *currentIndex);
void branchIfEqual(int lineNumber, int *currentIndex, int numInstructions);

int main() {
    const char *inputFilePath = "C:\\Users\\user\\Desktop\\cal\\Calculator13\\input.txt";
    executeInstructions(inputFilePath);
    return 0;
}

void executeInstructions(const char *filePath) {
    Instruction *instructions = NULL;
    int numInstructions = 0;
    int currentIndex = 0;
    char inst_reg[MAX_INSTRUCTION_LENGTH]; 
    FILE *file = fopen(filePath, "r");
    if (!file) {
        perror("Error opening file");
        exit(1);
    }

    char tempInstruction[MAX_INSTRUCTION_LENGTH];
    while (fgets(tempInstruction, sizeof(tempInstruction), file) != NULL) {
        numInstructions++;
    }

    instructions = (Instruction *)malloc(numInstructions * sizeof(Instruction));
    rewind(file);

    int i = 0;
    while (fgets(instructions[i].instruction, MAX_INSTRUCTION_LENGTH, file) != NULL) {
        i++;
    }

    while (currentIndex < numInstructions) {
        strncpy(inst_reg, instructions[currentIndex].instruction, MAX_INSTRUCTION_LENGTH); 
        parseAndExecuteInstruction(inst_reg, &currentIndex, numInstructions); 
        currentIndex++;
    }

    fclose(file);
    free(instructions);
}


void parseAndExecuteInstruction(const char *instruction, int *currentIndex, int numInstructions) {
 
    char op; 
    char operand1Str[MAX_INSTRUCTION_LENGTH], operand2Str[MAX_INSTRUCTION_LENGTH]; 
    int operand1, operand2, isRegister1, isRegister2, value1, value2, i = 0; 


    if (sscanf(instruction, "%c %s %s", &op, operand1Str, operand2Str) < 1) {
        printf("Invalid instruction format: %s", instruction);
        return;
    }


    if (op != 'H') {
        operand1 = parseOperand(operand1Str, &isRegister1, &value1, i++);
        operand2 = parseOperand(operand2Str, &isRegister2, &value2, i);
    }


    switch (op) {
        case '+': add(value1, isRegister1, value2, isRegister2); break;
        case '-': subtract(value1, isRegister1, value2, isRegister2); break;
        case '*': multiply(value1, isRegister1, value2, isRegister2); break;
        case '/': divide(value1, isRegister1, value2, isRegister2); break;
        case 'M': move(value1, isRegister1, value2, isRegister2); break;
        case 'C': compare(value1, isRegister1, value2, isRegister2); break;
        case 'J': jump(operand1, currentIndex); break;
        case 'B': branchIfEqual(operand1, currentIndex, numInstructions); break;
        case 'H': *currentIndex = numInstructions; break; 
        default: printf("Unsupported operation: %c\n", op); break;
    }
}



int parseOperand(const char *operand, int *isRegister, int *value, int i) {
    if (operand[0] == 'R')
{
        *isRegister = 1;
        sscanf(operand + 1, "%d", value);
        if (*value < NUM_REGISTERS) {
            number[i]=*value;
            *value = registers[*value];
        } else {
            printf("Error: Register index out of bounds.\n");
            *value = 0;
        }
    } else {
        *isRegister = 0;
        sscanf(operand, "%x", value);
    }
    return *value; 
}

void add(int operand1, int isRegister1, int operand2, int isRegister2) {
    int result = operand1 + operand2;
    registers[0] = result;
    printf("R0: %d = %d + %d\n", result, operand1, operand2);
}


void subtract(int operand1, int isRegister1, int operand2, int isRegister2) {
    int result = operand1 - operand2;
    registers[0] = result;
    printf("R0: %d = %d - %d\n", result, operand1, operand2);
}


void multiply(int operand1, int isRegister1, int operand2, int isRegister2) {
    int result = operand1 * operand2;
    registers[0] = result;
    printf("R0: %d = %d * %d\n", result, operand1, operand2);
}


void divide(int operand1, int isRegister1, int operand2, int isRegister2) {

    if (operand2 == 0) {
        printf("Error: Division by zero.\n");
        return;
    }
    
    int result = operand1 / operand2;
    registers[0] = result;
    printf("R0: %d = %d / %d\n", result, operand1, operand2);
}


void move(int operand1, int isRegister1, int operand2, int isRegister2) {
    if (!isRegister1) {
        printf("Error: First operand must be a register.\n");
        return;
    }

    int num1 = number[0];   
    int num2 = number[1];

    if (isRegister2) {
        registers[num1] = registers[num2];
    } else {

        registers[num1] = operand2; 
    }

    int registerIndex = isRegister2 ? operand2 : operand1;
    printf("R%d: %d\n", num1, registers[num1]);
}


void compare(int operand1, int isRegister1, int operand2, int isRegister2) {
    int result;
    if (operand1 == operand2) {
        result = 0; 
    } else if (operand1 > operand2) {
        result = 0; 
    } else {
        result = 1; 
    }
    registers[0] = result;
    printf("Comparison Result in R0: %d\n", result);
}


void jump(int lineNumber, int *currentIndex) {
    *currentIndex = lineNumber - 1;
}

void branchIfEqual(int lineNumber, int *currentIndex, int numInstructions) {
    if (registers[0] == 1 && lineNumber - 1 < numInstructions) {
        *currentIndex = lineNumber - 1;
    }
}