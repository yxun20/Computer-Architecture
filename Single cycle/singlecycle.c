#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
//현재 최고
// Register Number
#define zero_reg 0  
#define at_reg 1    
#define v0_reg 2    
#define v1_reg 3    
#define a0_reg 4    
#define a1_reg 5
#define a2_reg 6
#define a3_reg 7
#define t0_reg 8    
#define t1_reg 9
#define t2_reg 10
#define t3_reg 11
#define t4_reg 12
#define t5_reg 13
#define t6_reg 14
#define t7_reg 15
#define s0_reg 16   
#define s1_reg 17
#define s2_reg 18
#define s3_reg 19
#define s4_reg 20
#define s5_reg 21
#define s6_reg 22
#define s7_reg 23
#define t8_reg 24   
#define t9_reg 25
#define k0_reg 26   
#define k1_reg 27   
#define gp_reg 28   
#define sp_reg 29   
#define fp_reg 30   
#define ra_reg 31   

// opcode
#define opcode_r_type  0x0   
#define opcode_addi    0x8   
#define opcode_addiu   0x9   
#define opcode_andi    0xc
#define opcode_lw      0x23
#define opcode_sw      0x2b
#define opcode_ori     0xd
#define opcode_lui     0xf
#define opcode_slti    0xa
#define opcode_sltiu   0xb
#define opcode_j       0x2   
#define opcode_jal     0x3
#define opcode_beq     0x4
#define opcode_bne     0x5

// funct
#define funct_add     0x20
#define funct_addu    0x21
#define funct_sub     0x22
#define funct_subu    0x23
#define funct_and     0x24
#define funct_nor     0x27
#define funct_or      0x25
#define funct_jr      0x08
#define funct_slt     0x2a
#define funct_sltu    0x2b
#define funct_sll     0x00
#define funct_srl     0x02

// Structure 'Instrucion'
typedef struct instrucion{
  uint32_t jump_address;   
  uint16_t immediate_value;   
  uint8_t function_code;      
  uint8_t shift_amount;     
  uint8_t rd;         
  uint8_t rt;         
  uint8_t rs;        
  uint8_t opcode;     
}Instrucion;

// Structure 'Processor' 
uint32_t *registers;                
int PC;                       
uint32_t instruction_register;                  
uint8_t *instruction_memory;            
uint8_t *data_memory;            
int num_r_type_executions;               
int num_i_type_executions;              
int num_j_type_executions;              
int *instruction_types;                                          
int cycle_count;                
int branch_taken_count;         
int memory_access_count;      

// Structure 'ALUOutput'
typedef struct output{
  uint32_t read_data1;
  uint32_t read_data2;
  uint32_t alu_src_mux_output;
  uint32_t immediate_extension;
  uint32_t alu_result;
  uint32_t memory_data_read;
  unsigned int zero_flag;
}ALUOutput;

// Structure 'ControlUnit'
typedef struct cu{
  unsigned int dest_reg_sel : 2;
  unsigned int jump_control : 2;
  unsigned int branch_control : 1;
  unsigned int mem_read_enable : 1;
  unsigned int mem_to_reg_select : 1;
  unsigned int mem_write_enable : 1;
  unsigned int alu_src : 1;
  unsigned int reg_write_enable : 1;
    // New signal
  unsigned int jump_link : 1;
  unsigned int zero_extension : 1;
  unsigned int shift_control : 1;
}ControlUnit;


// 0.Preprocess
void initialize_processor(Instrucion* inst, ControlUnit* cu, ALUOutput* output);
void loda_instructions_into_memory(void);
// 1.Fetch
void fetch();
// 2.Decode
void decode(Instrucion* inst, ControlUnit* cu, ALUOutput* output);
// 3.Execution
void execute(Instrucion* inst, ControlUnit* cu, ALUOutput* output);
// 4.Load/Store result to memory
void access_memory(Instrucion* inst, ControlUnit* cu, ALUOutput* output);
// 5.Write Back
void write_back(Instrucion* inst, ControlUnit* cu, ALUOutput* output);

void update_processor_state(Instrucion* inst, ControlUnit* cu, ALUOutput* output);

void parse_opcode(Instrucion* inst);
// Sign Extension
uint32_t extend_immediate_arithmetic(uint16_t immediate_value);
uint32_t extend_immediate_logical(uint16_t immediate_value);

// Control Unit
void generate_control_signals(Instrucion* inst, ControlUnit* cu);
// Auxiliary functions to generate appropriate control signal
unsigned int is_register_write_r_type(Instrucion* inst);

// ALU
char determine_alu_operation(Instrucion* inst, ControlUnit* cu);
void alu(char alu_ops, ALUOutput* output, uint32_t alu_input1, uint32_t alu_input2);

// MUX
uint8_t Mux_RegDest(unsigned int dest_reg_sel, uint8_t return_addr, uint8_t rd, uint8_t rt);
uint32_t Mux_ALUsrc(unsigned int alu_src, uint32_t immediate_extension, uint32_t rd2);
uint32_t Mux_Branch(unsigned int pc_src, uint32_t target, uint32_t add4);
uint32_t Mux_Jump(unsigned int jump_control, uint32_t reg_rs, uint32_t jump_addr, uint32_t mux_branch);
uint32_t Mux_MemToReg(unsigned int mem_to_reg_select, uint32_t read_data, uint32_t alu_res);
uint32_t Mux_Zero_Extend(unsigned int zero_extension, uint32_t zero_extended, uint32_t sign_extended);
uint32_t Mux_Shift(unsigned int shift_control, uint8_t shift_amount, uint32_t reg_rs);
uint32_t Mux_JumpAndLink(unsigned int jump_link, uint32_t ra_PC, uint32_t reg_write_data);

// Print out the result of executing all instructions
void display_execution_results(void);
// Protect memory leakage
void free_allocated_memory(Instrucion* inst, ControlUnit* cu, ALUOutput* output);

// Main
int main(void){

  Instrucion instruction;
  Instrucion* inst = &instruction;
  ControlUnit control_unit;
  ControlUnit* cu = &control_unit;
  ALUOutput out_put;
  ALUOutput* output = &out_put;
  loda_instructions_into_memory();
  initialize_processor(inst, cu, output);

  while(PC != 0xffffffff){
    for(int i = 0; i < 3; i++){ instruction_types[i] = 0; }
    printf("\n[%d] Cycle : (PC:0x%x)\n", cycle_count+1, PC);

    fetch();

    decode(inst, cu, output); // Control Unit

    execute(inst, cu, output); // ALU Control & Operation //

    access_memory(inst, cu, output);

    write_back(inst, cu, output);
    update_processor_state(inst, cu, output);
  }

  display_execution_results();
  free_allocated_memory(inst, cu, output);
  return 0;
}

void loda_instructions_into_memory(void) {
    FILE* bin_file;
    const char* filename = "C:\\Users\\user\\Desktop\\Single cycle\\simple2.bin"; 

    bin_file = fopen(filename, "rb");
    if (bin_file == NULL) {
        printf("Error, Unable to open the binary file\n");
        exit(1);
    }

    fseek(bin_file, 0, SEEK_END);
    long bin_file_size = ftell(bin_file);
    fseek(bin_file, 0, SEEK_SET);

    instruction_memory = (uint8_t*)malloc(bin_file_size);

    fread(instruction_memory, bin_file_size, 1, bin_file);

    fclose(bin_file);
    return;
}

void initialize_processor(Instrucion* inst, ControlUnit* cu, ALUOutput* output){

    registers = (uint32_t*)malloc(32 * sizeof(uint32_t));
    if (registers == NULL) {
        printf("Error, Memory allocation for register array unsuccessful\n");
        exit(1);
    }

    data_memory = (uint8_t*)malloc(0x10000000 * sizeof(uint8_t));
    if (data_memory == NULL) {
        printf("Error, Unable to allocate memory for data_memory array\n");
        free(registers);
        exit(1);
    }

    instruction_types = (int*)malloc(3 * sizeof(int));
    if (instruction_types == NULL) {
        printf("Error, Memory allocation failure for the instruction_types array\n");
        free(registers);
        free(data_memory);
        exit(1);
    }

    num_r_type_executions = 0;
    num_i_type_executions = 0;
    num_j_type_executions = 0;
    cycle_count = 0;
    branch_taken_count = 0;
    memory_access_count = 0;

    memset(instruction_types, 0, 3 * sizeof(int));
    *inst = (Instrucion){0}; 
    *cu = (ControlUnit){0}; 
    *output = (ALUOutput){0}; 

    memset(registers, 0, 32 * sizeof(uint32_t));
    registers[ra_reg] = 0xffffffff;  
    registers[sp_reg] = 0x10000000;  

    memset(data_memory, 0, 0x10000000 * sizeof(uint8_t));
    PC = 0x00000000;
    instruction_register = 0x00000000;
}



void fetch(void) {
    instruction_register = 0;
    for (int i = 0; i < 4; i++) {
        instruction_register = (instruction_register << 8) | instruction_memory[PC + i];
    }
    PC += 4;
    printf("[Fetch Instruction] -> (0x%08x)\n", instruction_register);
}

void decode(Instrucion* inst, ControlUnit* cu, ALUOutput* output) {
    parse_opcode(inst);
    generate_control_signals(inst, cu);
    if (instruction_register == 0x00000000) {
        printf("[Decode Instruction] -> nop\n");
        return;
    }
    output->read_data1 = registers[inst->rs];
    output->immediate_extension = extend_immediate_logical(inst->immediate_value);
    output->immediate_extension = extend_immediate_arithmetic(output->immediate_extension);
    output->read_data2 = registers[inst->rt];
    output->alu_src_mux_output = Mux_ALUsrc(cu->alu_src, output->immediate_extension, output->read_data2);
    if (instruction_types[0] == 1) {
        num_r_type_executions++;
        printf("[Decode Instruction] -> (type : R)\n");
        printf("\topcode : 0x%x, ", inst->opcode);
        printf("rs : 0x%x (R[%d] <- 0x%x), ", inst->rs, inst->rs, registers[inst->rs]);
        printf("rt : 0x%x (R[%d] <- 0x%x), ", inst->rt, inst->rt, registers[inst->rt]);
        printf("rd : 0x%x (%d), ", inst->rd, inst->rd);
        printf("shift_amount : 0x%x, ", inst->shift_amount);
        printf("function_code : 0x%x\n", inst->function_code);
    } else if (instruction_types[1] == 1) {
        num_i_type_executions++;
        printf("[Decode Instruction] -> (type : I)\n");
        printf("\topcode : 0x%x, ", inst->opcode);
        printf("rs : 0x%x (R[%d] <- 0x%x), ", inst->rs, inst->rs, registers[inst->rs]);
        printf("rt : 0x%x (R[%d] <- 0x%x), ", inst->rt, inst->rt, registers[inst->rt]);
        printf("imm : 0x%x\n", inst->immediate_value);
    } else if (instruction_types[2] == 1) {
        num_j_type_executions++;
        printf("[Decode Instruction] -> (type : J)\n");
        printf("\topcode : 0x%x, ", inst->opcode);
        printf("addr : 0x%x\n", inst->jump_address);
    }
}

void execute(Instrucion* inst, ControlUnit* cu, ALUOutput* output) {
    alu(determine_alu_operation(inst, cu), output, output->read_data1, output->alu_src_mux_output);
}

void access_memory(Instrucion* inst, ControlUnit* cu, ALUOutput* output) {
    uint32_t address = output->alu_result;
    if (cu->mem_write_enable) {
        for (int i = 0; i < 4; i++) {
            data_memory[address + (3 - i)] = (output->read_data2 >> (8 * i)) & 0xff;
        }
        printf("[Store] : Mem[0x%08x] <- r[%d] = 0x%08x\n", address, inst->rt, output->read_data2);
    } else if (cu->mem_read_enable) {
        output->memory_data_read = 0;
        for (int i = 0; i < 4; i++) {
            output->memory_data_read = (output->memory_data_read << 8) + data_memory[address + i];
        }
        printf("[Load] : r[%d] <- Mem[0x%08x] = 0x%08x\n", inst->rt, address, output->memory_data_read);
    }
}

void write_back(Instrucion* inst, ControlUnit* cu, ALUOutput* output) {
    uint32_t reg_write_data = Mux_MemToReg(cu->mem_to_reg_select, output->memory_data_read, output->alu_result);
    if (cu->reg_write_enable) {
        uint8_t destination_register = Mux_RegDest(cu->dest_reg_sel, ra_reg, inst->rd, inst->rt);
        reg_write_data = Mux_JumpAndLink(cu->jump_link, PC + 4, reg_write_data);
        registers[destination_register] = reg_write_data;
        if (cu->jump_link) {
            printf("[Write Back] : r[%d] <- 0x%08x = 0x%08x + 8\n", ra_reg, PC + 4, PC - 4);
        } else {
            printf("[Write Back] : r[%d] <- 0x%08x\n", destination_register, reg_write_data);
        }
    }
}


void update_processor_state(Instrucion* inst, ControlUnit* cu, ALUOutput* output) {
    uint32_t print_PC = PC;
    uint32_t jump_addr = (inst->jump_address << 2) | (PC & 0xf0000000);
    uint32_t branch_target = (output->immediate_extension << 2) + PC;
    PC = Mux_Jump(cu->jump_control, registers[inst->rs], jump_addr, Mux_Branch(cu->branch_control & output->zero_flag, branch_target, PC));

    if (cu->jump_control) {
        if (inst->function_code == funct_jr) {
            printf("[PCs Update] : (Jump) PC = 0x%08x <- rs : R[%d] = 0x%08x\n", PC, inst->rs, registers[inst->rs]);
        } else {
            printf("[PC Update] : (Jump) PC <- 0x%08x = (0x%08x << 2) | ((0x%08x+4) & 0xf0000000)\n", PC, inst->jump_address, print_PC - 4);
        }
    } else if (cu->branch_control && output->zero_flag) {
        branch_taken_count++;
        printf("[PC Update] : (Branch Taken) PC <- 0x%08x = (0x%08x << 2) + 0x%08x (= 0x%08x+4)\n", PC, output->immediate_extension, print_PC, print_PC - 4);
    } else {
        printf("[PC Update] : PC <- 0x%08x = 0x%08x+4\n", PC, print_PC);
    }
    cycle_count++;
}

void parse_opcode(Instrucion* inst) {
    inst->opcode = (instruction_register >> 26) & 0x0000003f;
    inst->rs = (instruction_register >> 21) & 0x0000001f;
    inst->rt = (instruction_register >> 16) & 0x0000001f;
    inst->rd = (instruction_register >> 11) & 0x0000001f;
    inst->shift_amount = (instruction_register >> 6) & 0x0000001f;
    inst->function_code = instruction_register & 0x0000003f;
    inst->immediate_value = instruction_register & 0x0000ffff;
    inst->jump_address = instruction_register & 0x03ffffff;
}

uint32_t extend_immediate_arithmetic(uint16_t immediate_value) {
    if ((immediate_value >> 15) & 0x1) {
        return immediate_value | 0xffff0000;
    }
    return immediate_value;
}

uint32_t extend_immediate_logical(uint16_t immediate_value) {
    return immediate_value;
}

void generate_control_signals(Instrucion* inst, ControlUnit* cu) {
    if (instruction_register == 0x00000000) {
        cu->jump_control = 0;
        cu->dest_reg_sel = 0;
        cu->branch_control = 0;
        cu->mem_read_enable = 0;
        cu->mem_to_reg_select = 0;
        cu->mem_write_enable = 0;
        cu->alu_src = 0;
        cu->reg_write_enable = 0;
        cu->jump_link = 0;
        cu->zero_extension = 0;
        cu->shift_control = 0;
    } else {
        switch (inst->opcode) {
            case opcode_j:
            case opcode_jal:
                cu->jump_control = 1;
                instruction_types[2] = 1;
                break;
            case opcode_r_type:
                if (inst->function_code == funct_jr) {
                    cu->jump_control = 2; 
                } else {
                    cu->jump_control = 0; 
                }
                instruction_types[0] = 1;
                break;
            default:
                cu->jump_control = 0;
                break;
        }


        switch (inst->opcode) {
            case opcode_r_type:
                cu->dest_reg_sel = 1;
                instruction_types[0] = 1;
                break;
            case opcode_jal:
                cu->dest_reg_sel = 2;
                instruction_types[2] = 1;
                break;
            default:
                cu->dest_reg_sel = 0;
                break;
        }

        switch (inst->opcode) {
            case opcode_beq:
            case opcode_bne:
                cu->branch_control = 1;
                instruction_types[1] = 1;
                break;
            default:
                cu->branch_control = 0;
                break;
        }

        switch (inst->opcode) {
            case opcode_lui:
            case opcode_lw:
                cu->mem_read_enable = 1;
                instruction_types[1] = 1;
                memory_access_count += 1;
                break;
            default:
                cu->mem_read_enable = 0;
                break;
        }

        switch (inst->opcode) {
            case opcode_lui:
            case opcode_lw:
                cu->mem_to_reg_select = 1;
                instruction_types[1] = 1;
                break;
            default:
                cu->mem_to_reg_select = 0;
                break;
        }

        switch (inst->opcode) {
            case opcode_sw:
                cu->mem_write_enable = 1;
                instruction_types[1] = 1;
                memory_access_count += 1;
                break;
            default:
                cu->mem_write_enable = 0;
                break;
        }

        switch (inst->opcode) {
            case opcode_addi:
            case opcode_addiu:
            case opcode_andi:
            case opcode_lui:
            case opcode_lw:
            case opcode_ori:
            case opcode_slti:
            case opcode_sltiu:
            case opcode_sw:
                cu->alu_src = 1;
                instruction_types[1] = 1;
                break;
            default:
                cu->alu_src = 0;
                break;
        }

        switch (inst->opcode) {
            case opcode_r_type:
                cu->reg_write_enable = is_register_write_r_type(inst);
                instruction_types[0] = 1;
                break;
            case opcode_addi:
            case opcode_addiu:
            case opcode_andi:
            case opcode_lui:
            case opcode_lw:
            case opcode_ori:
            case opcode_slti:
            case opcode_sltiu:
            case opcode_jal:
                cu->reg_write_enable = 1;
                instruction_types[1 + (inst->opcode == opcode_jal)] = 1;
                break;
            default:
                cu->reg_write_enable = 0;
                break;
        }

        cu->jump_link = (inst->opcode == opcode_jal) ? 1 : 0;
        if (inst->opcode == opcode_jal) instruction_types[2] = 1;

        switch (inst->opcode) {
            case opcode_andi:
            case opcode_ori:
                cu->zero_extension = 1;
                instruction_types[1] = 1;
                break;
            default:
                cu->zero_extension = 0;
                break;
        }

        if (inst->opcode == opcode_r_type) {
            if (inst->function_code == funct_sll || inst->function_code == funct_srl) {
                cu->shift_control = 1; 
            } else {
                cu->shift_control = 0; 
            }
            instruction_types[0] = 1;
        } else {
            cu->shift_control = 0;
        }
    }
    return;
}

unsigned int is_register_write_r_type(Instrucion* inst){
  switch(inst->function_code){
    case (funct_add):
    case (funct_addu):
    case (funct_and):
    case (funct_nor):
    case (funct_or):
    case (funct_slt):
    case (funct_sltu):
    case (funct_sll):
    case (funct_srl):
    case (funct_sub):
    case (funct_subu):
      return 1;
    case (funct_jr):
      return 0;
    default:
      printf("Error, No matching operation found\n");
      exit(1);
  }
}

char determine_alu_operation(Instrucion* inst, ControlUnit* cu) {
    switch (inst->opcode) {
        case opcode_r_type:
            switch (inst->function_code) {
                case funct_add:
                case funct_addu:
                    return 1;
                case funct_and:
                    return 2;
                case funct_or:
                    return 5;
                case funct_slt:
                case funct_sltu:
                    return 6;
                case funct_sll:
                    return 7;
                case funct_srl:
                    return 8;
                case funct_sub:
                case funct_subu:
                    return 9;
                case funct_nor:
                    return 4;
                case funct_jr:
                    return 0;
                default:
                    printf("Error, No corresponding operation available\n");
                    exit(1);
            }
        case opcode_addi:
        case opcode_addiu:
        case opcode_lw:
        case opcode_sw:
            return 1;
        case opcode_beq:
            return 10;
        case opcode_bne:
            return 11;
        case opcode_andi:
            return 2;
        case opcode_ori:
            return 5;
        case opcode_slti:
        case opcode_sltiu:
            return 6;
        case opcode_lui:
            return 12;
        case opcode_j:
        case opcode_jal:
            return 0;
        default:
            printf("Error, Operation not found\n");
            exit(1);
    }
}


void alu(char alu_ops, ALUOutput* output, uint32_t alu_input1, uint32_t alu_input2) {
    switch (alu_ops) {
        case 0:  // J type instruction (No ALU operation)
            break;
        case 1:  // funct_add, opcode_addi, opcode_addiu, opcode_lw, opcode_sw
            output->alu_result = alu_input1 + alu_input2;
            break;
        case 2:  // and, opcode_andi
            output->alu_result = alu_input1 & alu_input2;
            break;
        case 4:  // funct_nor
            output->alu_result = ~(alu_input1 | alu_input2);
            break;
        case 5:  // or, opcode_ori
            output->alu_result = alu_input1 | alu_input2;
            break;
        case 6:  // funct_slt, opcode_slti, opcode_sltiu
            output->alu_result = alu_input1 < alu_input2;
            break;
        case 7:  // funct_sll
            output->alu_result = alu_input2 << alu_input1;
            break;
        case 8:  // funct_srl
            output->alu_result = alu_input2 >> alu_input1;
            break;
        case 9:  // funct_sub, funct_subu
            output->alu_result = alu_input1 - alu_input2;
            break;
        case 10: // opcode_beq
            output->zero_flag = (alu_input1 - alu_input2 == 0);
            break;
        case 11: // opcode_bne
            output->zero_flag = (alu_input1 - alu_input2 != 0);
            break;
        case 12: // opcode_lui
            output->alu_result = alu_input2 << 16;
            break;
        default:
            printf("Error, Matching operation not found\n");
            exit(1);
    }
    return;
}

uint8_t Mux_RegDest(unsigned int dest_reg_sel, uint8_t return_addr, uint8_t rd, uint8_t rt) {
    switch (dest_reg_sel) {
        case 2: return return_addr;
        case 1: return rd;
        default: return rt;
    }
}

uint32_t Mux_ALUsrc(unsigned int alu_src, uint32_t immediate_extension, uint32_t rd2) {
    instruction_types[1] = alu_src;  // Document that we are using an I-type instruction
    return alu_src ? immediate_extension : rd2;
}

uint32_t Mux_Branch(unsigned int pc_src, uint32_t target, uint32_t add4) {
    return pc_src ? target : add4;
}

uint32_t Mux_Jump(unsigned int jump_control, uint32_t reg_rs, uint32_t jump_addr, uint32_t mux_branch) {
    switch (jump_control) {
        case 2: return reg_rs;
        case 1: return jump_addr;
        case 0: return mux_branch;
        default:
            printf("Error, Jump control signal is invalid\n");
            exit(1);
    }
}

uint32_t Mux_MemToReg(unsigned int mem_to_reg_select, uint32_t read_data, uint32_t alu_res) {
    return mem_to_reg_select ? read_data : alu_res;
}

uint32_t Mux_Zero_Extend(unsigned int zero_extension, uint32_t zero_extended, uint32_t sign_extended) {
    return zero_extension ? zero_extended : sign_extended;
}

uint32_t Mux_Shift(unsigned int shift_control, uint8_t shift_amount, uint32_t reg_rs) {
    return shift_control ? (shift_amount << reg_rs) : reg_rs;
}

uint32_t Mux_JumpAndLink(unsigned int jump_link, uint32_t ra_PC, uint32_t reg_write_data) {
    return jump_link ? ra_PC : reg_write_data;
}


void display_execution_results(){
  printf("\n\n\n");
  printf("Return Value (R[2]) : %d\n", registers[v0_reg]);
  printf("Total Cycle : %d\n", cycle_count);
  printf("[R Instructions] : %d\n", num_r_type_executions);
  printf("[I Instructions] : %d\n", num_i_type_executions);
  printf("[J Instructions] : %d\n", num_j_type_executions);
  printf("Number of Memory Access Instructions : %d\n", memory_access_count);
  printf("Number of Branch Taken : %d\n", branch_taken_count);
  return;
}

void free_allocated_memory(Instrucion* inst, ControlUnit* cu, ALUOutput* output){
  free(registers);
  free(instruction_memory);
  free(data_memory);
  free(instruction_types);
  return;
}