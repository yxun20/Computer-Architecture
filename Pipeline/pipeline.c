#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEM_SIZE 0xFFFFFFFF

#define SHIFT_LEFT_LOGICAL     0x00
#define SHIFT_RIGHT_LOGICAL    0x02
#define SHIFT_RIGHT_ARITHMETIC 0x03
#define SHIFT_LEFT_LOGICAL_VAR 0x04
#define SHIFT_RIGHT_LOGICAL_VAR 0x06
#define SHIFT_RIGHT_ARITHMETIC_VAR 0x07
#define JUMP_REGISTER          0x08
#define JUMP_AND_LINK_REGISTER 0x09
#define MOVE_IF_ZERO           0x0a
#define MOVE_IF_NOT_ZERO       0x0b
#define ADDITION               0x20
#define ADDITION_UNSIGNED      0x21
#define SUBTRACTION            0x22
#define SUBTRACTION_UNSIGNED   0x23
#define AND_OPERATION          0x24
#define OR_OPERATION           0x25
#define XOR_OPERATION          0x26
#define NOR_OPERATION          0x27
#define SET_LESS_THAN          0x2a
#define SET_LESS_THAN_UNSIGNED 0x2b

#define ALU_AND       0x00
#define ALU_OR        0x01
#define ALU_ADD       0x02
#define ALU_SLL       0x04
#define ALU_XOR       0x05
#define ALU_NOR       0x06
#define ALU_SRL       0x07
#define ALU_SRA       0x08
#define ALU_SUB       0x12
#define ALU_SLT       0x13
#define ALU_SLLV      0x24
#define ALU_SRLV      0x27
#define ALU_SRAV      0x28

#define INSTRUCTION_TYPE_R 0x00
#define BRANCH_LESS_THAN_ZERO 0x01
#define JUMP                 0x02
#define JUMP_AND_LINK        0x03
#define BRANCH_EQUAL         0x04
#define BRANCH_NOT_EQUAL     0x05
#define BRANCH_LESS_EQUAL_ZERO 0x06
#define BRANCH_GREATER_THAN_ZERO 0x07
#define ADD_IMMEDIATE        0x08
#define ADD_IMMEDIATE_UNSIGNED 0x09
#define SET_LESS_THAN_IMMEDIATE 0x0a
#define SET_LESS_THAN_IMMEDIATE_UNSIGNED 0x0b
#define AND_IMMEDIATE        0x0c
#define OR_IMMEDIATE         0x0d
#define XOR_IMMEDIATE        0x0e
#define LOAD_UPPER_IMMEDIATE 0x0f
    
#define LOAD_BYTE            0x20
#define LOAD_HALFWORD        0x21
#define LOAD_WORD_LEFT       0x22
#define LOAD_WORD            0x23
#define LOAD_BYTE_UNSIGNED   0x24
#define LOAD_HALFWORD_UNSIGNED 0x25
#define LOAD_WORD_RIGHT      0x26
#define STORE_BYTE           0x28
#define STORE_HALFWORD       0x29
#define STORE_WORD_LEFT      0x2a
#define STORE_WORD           0x2b
#define STORE_WORD_RIGHT     0x2e

typedef struct {
    unsigned int opcode : 6;
    unsigned int source_register1 : 5;
    unsigned int source_register2 : 5;
    unsigned int shift_amount : 5;
    unsigned int function : 6;
    unsigned int destination_register : 5;
} R_type_instruction;

typedef struct {
    unsigned int opcode : 6;
    unsigned int source_register : 5;
    unsigned int target_register : 5;
    unsigned int immediate_value : 16;
} I_type_instruction;

typedef struct {
    unsigned int opcode : 6;
    unsigned int address : 26;
} J_type_instruction;

typedef struct _ALU_Control_Unit {
    unsigned int* alu_op;
    unsigned int* function_code;
    unsigned int alu_control;
    unsigned int* jal;
    unsigned int* jr;
} ALU_Control_Unit;

typedef struct _Control_Unit {
    unsigned int reg_dst;
    unsigned int reg_write;
    unsigned int alu_src;
    unsigned int alu_op;
    unsigned int mem_to_reg;
    unsigned int mem_write;
    unsigned int jump;
    unsigned int jal;
    unsigned int jr;
    unsigned int branch;
    unsigned int extra;
} Control_Unit;

typedef struct _Memory_Structure {
    char* mem;
    unsigned int text_start;
    unsigned int text_end;
    unsigned int data_start;
    unsigned int data_end;
} Memory_Structure;

typedef struct _Register_File {
    unsigned int* read_reg1;
    unsigned int* read_reg2;
    unsigned int read_data1;
    unsigned int read_data2;
    unsigned int* write_reg;
} Register_File;

typedef struct _Instruction_Register {
    unsigned int data;
    unsigned int opcode;
    unsigned int source_register1;
    unsigned int source_register2;
    unsigned int destination_register;
    unsigned int function;
    unsigned int immediate_value;
    unsigned int shift_amount;
    unsigned int address;
} Instruction_Register;

typedef struct _Register_Struct {
    unsigned int program_counter;
    Instruction_Register instruction_register;
    unsigned int general_purpose_reg[32];
    Register_File register_file;
} Register_Struct;

typedef struct _IFID_Latch {
    unsigned int valid;
    unsigned int data;
    unsigned int next_pc;
    unsigned int pre_taken;
    unsigned int branch_history_index;
    unsigned int branch_history_found;
} IFID_Latch;

typedef struct _IDEX_Latch {
    unsigned int valid;
    unsigned int read_data1;
    unsigned int read_data2;
    unsigned int opcode;
    unsigned int source_register1;
    unsigned int source_register2;
    unsigned int immediate_value;
    unsigned int destination_register;
    unsigned int shift_amount;
    unsigned int sign_extended_data;
    unsigned int zero_extended_data;
    unsigned int lui_shifted_data;
    unsigned int branch_history_index;
    unsigned int branch_history_found;
    unsigned int function;
    unsigned int next_pc;
    unsigned int address;
    unsigned int pre_taken;
    Control_Unit control;
} IDEX_Latch;

typedef struct _EXMEM_Latch {
    unsigned int valid;
    unsigned int read_data1;
    unsigned int read_data2;
    unsigned int branch_target;
    unsigned int destination_register;
    unsigned int alu_result;
    unsigned int next_pc;
    struct {
        unsigned int zero;
        unsigned int negative;
        unsigned int greater_than_zero;
        unsigned int less_equal_zero;
    } flags;
    Control_Unit control;
} EXMEM_Latch;

typedef struct _MEMWB_Latch {
    unsigned int valid;
    unsigned int destination_register;
    unsigned int alu_result;
    unsigned int read_data;
    unsigned int next_pc;
    Control_Unit control;
} MEMWB_Latch;

typedef struct _Branch_History_Unit {
    unsigned int branch_instruction_address;
    unsigned int branch_target_address;
    unsigned int prediction_bit;
} Branch_History_Unit;

typedef struct _ALU_Struct {
    unsigned int* alu_control;
    unsigned int* input1;
    unsigned int* input2;
    unsigned int* shift_amount;
    unsigned int shift_amount_mux[2];
    unsigned int out_mux[9];
    unsigned int input2_mux[2];
    unsigned int result;
    struct {
        unsigned int zero;
        unsigned int negative;
        unsigned int greater_than_zero;
        unsigned int less_equal_zero;
    } alu_flags;
} ALU_Struct;

typedef struct _CPU_Struct {
    Register_Struct reg;
    IFID_Latch ifid_latch[2];
    IDEX_Latch idex_latch[2];
    EXMEM_Latch exmem_latch[2];
    MEMWB_Latch memwb_latch[2];
    Branch_History_Unit branch_history_unit[256];
    ALU_Control_Unit alu_control_unit;
    ALU_Struct alu_struct;
    unsigned int data_hazard_detected;
    unsigned int control_hazard_detected;
    unsigned int forwarding_unit[2];
    unsigned int* forwarding_mux[2];
    unsigned int* mux_write_reg[3];
    unsigned int* mux_alu_src[4];
    unsigned int mux_branchtaken[2];
    unsigned int mux_load[4];
    unsigned int mux_alu_result[2];
    unsigned int mux_branch[4];
    unsigned int mux_jump[2];
    unsigned int mux_jump_register[2];
    unsigned int mux_member_PC[2];
} CPU_Struct;

void init_memory(Memory_Structure* memory, unsigned int size, int text_start, int text_end, int data_start, int data_end);
int load_program(Memory_Structure* memory, char* dir);
int read_word(unsigned int address, char* mem);
unsigned int fetch_instruction_memory(Memory_Structure* memory, unsigned int address);
unsigned int fetch_data_memory(Memory_Structure* memory, unsigned int address);
void store_data_memory(Memory_Structure* memory, unsigned int address, unsigned int value, unsigned int count);
void cpu_init(CPU_Struct* cpu_struct);
void cpu_fetch(CPU_Struct* cpu_struct, Memory_Structure* mem);
void cpu_decode(CPU_Struct* cpu_struct);
void cpu_execute(CPU_Struct* cpu_struct);
void mem_access(CPU_Struct* cpu_struct, Memory_Structure* mem);
void write_back(CPU_Struct* cpu_struct, Memory_Structure* mem);
void detect_hazards(CPU_Struct* cpu_struct);
void latch_update(CPU_Struct* cpu_struct);
void branch_wait(CPU_Struct* cpu_struct, unsigned int branch_taken, unsigned int addr);
void prediction_and_execution(CPU_Struct* cpu_struct, unsigned int branch_taken, unsigned int addr);
void reg_file_ops(Register_Struct* reg, unsigned int* mux_out);
void reg_file_write(Register_Struct* reg, unsigned int write_reg, unsigned int write_data, unsigned int enable);
void alu_ctrl_ops(ALU_Control_Unit* acu);
void alu_ops(ALU_Struct* alu_struct, unsigned int* mux_out);
void control_unit_ops(Control_Unit* cu, int opcode);
void print_cycle(CPU_Struct* cpu_struct);
void print_fetch(CPU_Struct* cpu_struct, int tmp_pc);
void print_decode(CPU_Struct* cpu_struct);
void print_execute(CPU_Struct* cpu_struct);
void print_memory(CPU_Struct* cpu_struct);
void print_write_back(CPU_Struct* cpu_struct);
void print_fwd(CPU_Struct* cpu_struct);
void print_results(CPU_Struct* cpu_struct);

int cycle_count = 0, R_instruction_count = 0, I_instruction_count = 0, J_instruction_count = 0, branch_count = 0, memory_instruction_count = 0, stall_count = 0;

int main() {
    CPU_Struct cpu_struct;
    Memory_Structure memory;
    char* input_file = "C:\\Users\\user\\Desktop\\Single cycle\\input4.bin";
    
    cpu_struct.data_hazard_detected = 1; // Default: forwarding
    cpu_struct.control_hazard_detected = 1; // Default: ANT

    cpu_init(&cpu_struct);
    init_memory(&memory, MEM_SIZE , 0x0, 0x00100000, 0x00100001, 0x01001000);

    if(load_program(&memory, input_file)) return 0;

    while (cpu_struct.reg.program_counter != 0xFFFFFFFF) {
        mem_access(&cpu_struct, &memory);
        write_back(&cpu_struct, &memory);
        print_cycle(&cpu_struct);
        int tmp_pc = cpu_struct.reg.program_counter;
        cpu_fetch(&cpu_struct, &memory);
        print_fetch(&cpu_struct, tmp_pc);
        cpu_decode(&cpu_struct);
        print_decode(&cpu_struct);
        cpu_execute(&cpu_struct);
        print_execute(&cpu_struct);
        print_memory(&cpu_struct);
        print_write_back(&cpu_struct);
        detect_hazards(&cpu_struct);
        print_fwd(&cpu_struct);
        latch_update(&cpu_struct);
    }
    print_results(&cpu_struct);

    return 0;
}

void init_memory(Memory_Structure* memory, unsigned int size, int text_start, int text_end, int data_start, int data_end) {
    memory->mem = (char*)calloc(size, 1);
    memory->text_start = text_start;
    memory->text_end = text_end;
    memory->data_start = data_start;
    memory->data_end = data_end;
}

int load_program(Memory_Structure* memory, char* dir) {
    FILE* file = fopen(dir, "rb");
    if (file == NULL) {
        printf("[ERROR] input file error\n");
        return 1;
    }
    fread(memory->mem + memory->text_start, 1, memory->text_end - memory->text_start, file);
    fclose(file);
    return 0;
}

int read_word(unsigned int address, char* mem) {
    int ret = 0;
    for (int i = 0; i < 4; i++) {
        ret = ret << 8;
        ret = ret | (mem[address + i] & 0xff);
    }
    return ret;
}

unsigned int fetch_instruction_memory(Memory_Structure* memory, unsigned int addr) {
    if ((memory->text_end >= addr) && (addr >= memory->text_start))
        return read_word(addr, memory->mem);
    else
        return 0;
}

unsigned int fetch_data_memory(Memory_Structure* memory, unsigned int addr) {
    if ((memory->data_end >= addr) && (addr >= memory->data_start))
        return read_word(addr, memory->mem);
    else
        return 0;
}

void store_data_memory(Memory_Structure* memory, unsigned int addr, unsigned int value, unsigned int count) {
    if ((memory->data_end >= addr + count) && (addr >= memory->data_start)) {
        int tmp = value << 8 * (3 - count);
        for (int i = 0; i <= count; i++) {
            memory->mem[addr + i] = (tmp >> 24) & 0xff;
            tmp = tmp << 8;
        }
    }
    else
        return;
}

void cpu_init(CPU_Struct* cpu_struct) {
    cpu_struct->reg.program_counter = 0;

    for (int i = 0; i < 32; i++) 
        cpu_struct->reg.general_purpose_reg[i] = 0;
    
    cpu_struct->reg.general_purpose_reg[29] = 0x01000000;
    cpu_struct->reg.general_purpose_reg[31] = 0xffffffff;

    for (int i = 0; i < 2; i++) {
        memset(&(cpu_struct->ifid_latch[i]), 0, sizeof(IFID_Latch));
        memset(&(cpu_struct->idex_latch[i]), 0, sizeof(IDEX_Latch));
        memset(&(cpu_struct->exmem_latch[i]), 0, sizeof(EXMEM_Latch));
        memset(&(cpu_struct->memwb_latch[i]), 0, sizeof(MEMWB_Latch));
    }

    cpu_struct->ifid_latch[0].valid = 0;
    cpu_struct->idex_latch[0].valid = 0;
    cpu_struct->exmem_latch[0].valid = 0;
    cpu_struct->memwb_latch[0].valid = 0;

    memset(&cpu_struct->branch_history_unit, -1, sizeof(Branch_History_Unit));

    for (int i = 0; i < 0x100; i++) 
        cpu_struct->branch_history_unit[i].prediction_bit = 0;

    cpu_struct->forwarding_unit[0] = 0;
    cpu_struct->forwarding_unit[1] = 0;

    cpu_struct->forwarding_mux[0] = &(cpu_struct->memwb_latch[1].alu_result);
    cpu_struct->forwarding_mux[1] = &(cpu_struct->memwb_latch[1].read_data);

    cpu_struct->reg.register_file.read_reg1 = &(cpu_struct->reg.instruction_register.source_register1);
    cpu_struct->reg.register_file.read_reg2 = &(cpu_struct->reg.instruction_register.source_register2);

    cpu_struct->alu_control_unit.alu_op = &(cpu_struct->idex_latch[1].control.alu_op);
    cpu_struct->alu_control_unit.function_code = &(cpu_struct->idex_latch[1].function);
    cpu_struct->alu_control_unit.jr = &(cpu_struct->idex_latch[1].control.jr);
    cpu_struct->alu_control_unit.jal = &(cpu_struct->idex_latch[1].control.jal);

    cpu_struct->alu_struct.alu_control = &(cpu_struct->alu_control_unit.alu_control);
    cpu_struct->alu_struct.shift_amount = &(cpu_struct->idex_latch[1].shift_amount);
    cpu_struct->alu_struct.input1 = &(cpu_struct->exmem_latch[0].read_data1);

    unsigned int* tmp_ra = (unsigned int*)malloc(4);
    *tmp_ra = 31; 

    cpu_struct->mux_write_reg[0] = &(cpu_struct->reg.instruction_register.source_register2);
    cpu_struct->mux_write_reg[1] = &(cpu_struct->reg.instruction_register.destination_register); 
    cpu_struct->mux_write_reg[2] = tmp_ra;

    cpu_struct->mux_alu_src[0] = &(cpu_struct->exmem_latch[0].read_data2);
    cpu_struct->mux_alu_src[1] = &(cpu_struct->idex_latch[1].sign_extended_data); 
    cpu_struct->mux_alu_src[2] = &(cpu_struct->idex_latch[1].zero_extended_data);
    cpu_struct->mux_alu_src[3] = &(cpu_struct->idex_latch[1].lui_shifted_data);
}

void cpu_fetch(CPU_Struct* cpu_struct, Memory_Structure* mem) {
    if (cpu_struct->reg.program_counter != 0xFFFFFFFF) {
        cpu_struct->ifid_latch[0].valid = 1;
        cpu_struct->ifid_latch[0].data = fetch_instruction_memory(mem, cpu_struct->reg.program_counter);
        cpu_struct->alu_control_unit.alu_control = 0;

        switch (cpu_struct->control_hazard_detected) {
            case 0: {
                cpu_struct->reg.program_counter += 4; 
                cpu_struct->ifid_latch[0].next_pc = cpu_struct->reg.program_counter;
            } break; // detect and wait
            case 1:
                cpu_struct->reg.program_counter = cpu_struct->reg.program_counter + 4;
                cpu_struct->ifid_latch[0].next_pc = cpu_struct->reg.program_counter;
                break; // ant
            case 2: {
                int branch_history_index = (0x100 - 1);
                branch_history_index <<= 2;
                branch_history_index &= cpu_struct->reg.program_counter;
                branch_history_index >>= 2;
                cpu_struct->ifid_latch[0].branch_history_index = branch_history_index;

                if (cpu_struct->reg.program_counter == cpu_struct->branch_history_unit[branch_history_index].branch_instruction_address) {
                    cpu_struct->ifid_latch[0].branch_history_found = 1;
                    cpu_struct->ifid_latch[0].next_pc = cpu_struct->reg.program_counter + 4;
                    cpu_struct->reg.program_counter = cpu_struct->branch_history_unit[branch_history_index].branch_target_address;
                } else {
                    cpu_struct->reg.program_counter = cpu_struct->reg.program_counter + 4;
                    cpu_struct->ifid_latch[0].branch_history_found = 0;
                    cpu_struct->ifid_latch[0].next_pc = cpu_struct->reg.program_counter;
                }
            } break; // alt
            case 3: {
                int branch_history_index = (0x100 - 1);
                branch_history_index <<= 2;
                branch_history_index &= cpu_struct->reg.program_counter;
                branch_history_index >>= 2;
                cpu_struct->ifid_latch[0].branch_history_index = branch_history_index;

                if (cpu_struct->reg.program_counter == cpu_struct->branch_history_unit[branch_history_index].branch_instruction_address) {
                    cpu_struct->ifid_latch[0].branch_history_found = 1;
                    switch (cpu_struct->branch_history_unit[branch_history_index].prediction_bit) {
                        case 0:
                            cpu_struct->ifid_latch[0].pre_taken = 0;
                            cpu_struct->reg.program_counter += 4;
                            cpu_struct->ifid_latch[0].next_pc = cpu_struct->reg.program_counter;
                            break;
                        case 1:
                            cpu_struct->ifid_latch[0].pre_taken = 1;
                            cpu_struct->ifid_latch[0].next_pc = cpu_struct->reg.program_counter + 4;
                            cpu_struct->reg.program_counter = cpu_struct->branch_history_unit[branch_history_index].branch_target_address;
                            break;
                    }
                } else {
                    cpu_struct->reg.program_counter += 4;
                    cpu_struct->ifid_latch[0].branch_history_found = 0;
                    cpu_struct->ifid_latch[0].pre_taken = 0;
                    cpu_struct->ifid_latch[0].next_pc = cpu_struct->reg.program_counter;
                }
            } break; // dynamic
            default:
                break;
        }
    }
}

void cpu_decode(CPU_Struct* cpu_struct) {
    if (cpu_struct->ifid_latch[1].valid) {
        unsigned int ins = cpu_struct->ifid_latch[1].data;
        R_type_instruction r_instruction;
        I_type_instruction i_instruction;
        J_type_instruction j_instruction;

        r_instruction.opcode = (ins >> 26) & 0x3F;
        r_instruction.source_register1 = (ins >> 21) & 0x1F;
        r_instruction.source_register2 = (ins >> 16) & 0x1F;
        r_instruction.destination_register = (ins >> 11) & 0x1F;
        r_instruction.shift_amount = (ins >> 6) & 0x1F;
        r_instruction.function = ins & 0x3F;

        i_instruction.opcode = (ins >> 26) & 0x3F;
        i_instruction.source_register = (ins >> 21) & 0x1F;
        i_instruction.target_register = (ins >> 16) & 0x1F;
        i_instruction.immediate_value = ins & 0xFFFF;

        j_instruction.opcode = (ins >> 26) & 0x3F;
        j_instruction.address = ins & 0x3FFFFFF;

        cpu_struct->reg.instruction_register.opcode = r_instruction.opcode;
        cpu_struct->reg.instruction_register.source_register1 = r_instruction.source_register1;
        cpu_struct->reg.instruction_register.source_register2 = r_instruction.source_register2;
        cpu_struct->reg.instruction_register.destination_register = r_instruction.destination_register;
        cpu_struct->reg.instruction_register.shift_amount = r_instruction.shift_amount;
        cpu_struct->reg.instruction_register.function = r_instruction.function;
        cpu_struct->reg.instruction_register.immediate_value = i_instruction.immediate_value;
        cpu_struct->reg.instruction_register.address = j_instruction.address;

        control_unit_ops(&(cpu_struct->idex_latch[0].control), cpu_struct->reg.instruction_register.opcode);

        reg_file_ops(&(cpu_struct->reg), (cpu_struct->mux_write_reg[cpu_struct->idex_latch[0].control.reg_dst]));
        cpu_struct->idex_latch[0].read_data1 = cpu_struct->reg.register_file.read_data1;
        cpu_struct->idex_latch[0].read_data2 = cpu_struct->reg.register_file.read_data2;

        cpu_struct->idex_latch[0].valid = 1;

        // connect unit
        cpu_struct->idex_latch[0].opcode = cpu_struct->reg.instruction_register.opcode;
        cpu_struct->idex_latch[0].source_register1 = cpu_struct->reg.instruction_register.source_register1;
        cpu_struct->idex_latch[0].source_register2 = cpu_struct->reg.instruction_register.source_register2;
        cpu_struct->idex_latch[0].destination_register = *(cpu_struct->reg.register_file.write_reg);
        cpu_struct->idex_latch[0].shift_amount = cpu_struct->reg.instruction_register.shift_amount;
        cpu_struct->idex_latch[0].function = cpu_struct->reg.instruction_register.function;
        cpu_struct->idex_latch[0].immediate_value = cpu_struct->reg.instruction_register.immediate_value;
        cpu_struct->idex_latch[0].next_pc = cpu_struct->ifid_latch[1].next_pc;
        cpu_struct->idex_latch[0].address = cpu_struct->reg.instruction_register.address;
        cpu_struct->idex_latch[0].sign_extended_data = (cpu_struct->reg.instruction_register.immediate_value & 0x8000) ? 
                                                 (cpu_struct->reg.instruction_register.immediate_value | 0xffff0000) : 
                                                 (cpu_struct->reg.instruction_register.immediate_value & 0x0000ffff);
        cpu_struct->idex_latch[0].zero_extended_data = cpu_struct->reg.instruction_register.immediate_value & 0x0000ffff;
        cpu_struct->idex_latch[0].lui_shifted_data = cpu_struct->reg.instruction_register.immediate_value << 16;

        cpu_struct->idex_latch[0].branch_history_found = cpu_struct->ifid_latch[1].branch_history_found;
        cpu_struct->idex_latch[0].branch_history_index = cpu_struct->ifid_latch[1].branch_history_index;
        cpu_struct->idex_latch[0].pre_taken = cpu_struct->ifid_latch[1].pre_taken;

        // j, jal
        cpu_struct->mux_jump[0] = cpu_struct->reg.program_counter;
        cpu_struct->mux_jump[1] = ((cpu_struct->ifid_latch[1].next_pc) & 0xf0000000) | (cpu_struct->idex_latch[0].address << 2);
        cpu_struct->reg.program_counter = cpu_struct->mux_jump[cpu_struct->idex_latch[0].control.jump];
    }
}

void cpu_execute(CPU_Struct* cpu_struct) {
    if (cpu_struct->idex_latch[1].valid) {
        cpu_struct->exmem_latch[0].control = cpu_struct->idex_latch[1].control;

        alu_ctrl_ops(&(cpu_struct->alu_control_unit));

        int fwd_data = *(cpu_struct->forwarding_mux[cpu_struct->memwb_latch[1].control.mem_to_reg]);
        unsigned int read_mux2[3] = { cpu_struct->idex_latch[1].read_data2, fwd_data, cpu_struct->exmem_latch[1].alu_result };
        unsigned int read_mux1[3] = { cpu_struct->idex_latch[1].read_data1, fwd_data, cpu_struct->exmem_latch[1].alu_result };

        cpu_struct->exmem_latch[0].read_data1 = read_mux1[cpu_struct->forwarding_unit[0]];
        cpu_struct->exmem_latch[0].read_data2 = read_mux2[cpu_struct->forwarding_unit[1]];

        alu_ops(&(cpu_struct->alu_struct), cpu_struct->mux_alu_src[cpu_struct->idex_latch[1].control.alu_src]);
        cpu_struct->exmem_latch[0].alu_result = cpu_struct->alu_struct.result;
        cpu_struct->exmem_latch[0].valid = 1;

        cpu_struct->exmem_latch[0].next_pc = cpu_struct->idex_latch[1].next_pc;
        cpu_struct->exmem_latch[0].flags.zero = cpu_struct->alu_struct.alu_flags.zero;
        cpu_struct->exmem_latch[0].flags.negative = cpu_struct->alu_struct.alu_flags.negative;
        cpu_struct->exmem_latch[0].flags.greater_than_zero = cpu_struct->alu_struct.alu_flags.greater_than_zero;
        cpu_struct->exmem_latch[0].flags.less_equal_zero = cpu_struct->alu_struct.alu_flags.less_equal_zero;
        cpu_struct->exmem_latch[0].branch_target = cpu_struct->idex_latch[1].next_pc + (cpu_struct->idex_latch[1].sign_extended_data << 2);
        cpu_struct->exmem_latch[0].destination_register = cpu_struct->idex_latch[1].destination_register;

        cpu_struct->mux_branch[2] = cpu_struct->exmem_latch[0].flags.less_equal_zero;
        cpu_struct->mux_branch[1] = !cpu_struct->exmem_latch[0].flags.zero;
        cpu_struct->mux_branch[0] = cpu_struct->exmem_latch[0].flags.zero;
        cpu_struct->mux_branch[3] = cpu_struct->exmem_latch[0].flags.greater_than_zero;

        unsigned int branch_mux_out = cpu_struct->exmem_latch[0].control.branch ? cpu_struct->mux_branch[cpu_struct->exmem_latch[0].control.extra & 0x3] : 0;

        cpu_struct->mux_branchtaken[0] = cpu_struct->reg.program_counter;
        cpu_struct->mux_branchtaken[1] = cpu_struct->exmem_latch[0].branch_target;
        unsigned int branch_taken_mux_out = cpu_struct->mux_branchtaken[branch_mux_out];

        prediction_and_execution(cpu_struct, branch_mux_out, branch_taken_mux_out);

        cpu_struct->mux_jump_register[0] = cpu_struct->reg.program_counter;
        cpu_struct->mux_jump_register[1] = cpu_struct->exmem_latch[0].alu_result;
        cpu_struct->reg.program_counter = cpu_struct->mux_jump_register[cpu_struct->idex_latch[1].control.jr];
    }
}

void mem_access(CPU_Struct* cpu_struct, Memory_Structure* mem) {
    if (cpu_struct->exmem_latch[1].valid) {
        cpu_struct->memwb_latch[0].control = cpu_struct->exmem_latch[1].control;

        if (cpu_struct->exmem_latch[1].control.mem_write) {
            store_data_memory(mem, cpu_struct->exmem_latch[1].alu_result, cpu_struct->exmem_latch[1].read_data2, cpu_struct->exmem_latch[1].control.extra);
        }

        if (cpu_struct->exmem_latch[1].control.mem_to_reg) {
            unsigned int lw = fetch_data_memory(mem, cpu_struct->exmem_latch[1].alu_result);
            unsigned int lb = (((cpu_struct->exmem_latch[1].control.extra) >> 2) & 1) ? ((int)lw >> 24) : (lw >> 24);
            unsigned int lh = (((cpu_struct->exmem_latch[1].control.extra) >> 2) & 1) ? ((int)lw >> 16) : (lw >> 16);

            cpu_struct->mux_load[3] = lw;
            cpu_struct->mux_load[0] = lb;
            cpu_struct->mux_load[1] = lh;
            cpu_struct->mux_load[2] = 0;

            cpu_struct->memwb_latch[0].read_data = cpu_struct->mux_load[(cpu_struct->exmem_latch[1].control.extra & 0x3)];
        }

        cpu_struct->memwb_latch[0].valid = 1;
        cpu_struct->memwb_latch[0].destination_register = cpu_struct->exmem_latch[1].destination_register;
        cpu_struct->memwb_latch[0].next_pc = cpu_struct->exmem_latch[1].next_pc;
        cpu_struct->memwb_latch[0].alu_result = cpu_struct->exmem_latch[1].alu_result;
    }
}

void write_back(CPU_Struct* cpu_struct, Memory_Structure* mem) {
    if (cpu_struct->memwb_latch[1].valid) {
        cpu_struct->mux_alu_result[0] = cpu_struct->memwb_latch[1].alu_result;
        cpu_struct->mux_alu_result[1] = cpu_struct->memwb_latch[1].read_data;

        cpu_struct->mux_member_PC[0] = cpu_struct->mux_alu_result[cpu_struct->memwb_latch[1].control.mem_to_reg];
        cpu_struct->mux_member_PC[1] = cpu_struct->memwb_latch[1].next_pc + 4;

        reg_file_write(&(cpu_struct->reg), cpu_struct->memwb_latch[1].destination_register, cpu_struct->mux_member_PC[cpu_struct->memwb_latch[1].control.jal], cpu_struct->memwb_latch[1].control.reg_write);
    }
}

void detect_hazards(CPU_Struct* cpu_struct) {
    cpu_struct->forwarding_unit[0] = 0b00;
    cpu_struct->forwarding_unit[1] = 0b00;

    // EXMEM hazard
    if (cpu_struct->exmem_latch[0].destination_register != 0 && cpu_struct->exmem_latch[0].control.reg_write) {
        if (cpu_struct->data_hazard_detected == 0) { // wait
            if ((cpu_struct->exmem_latch[0].destination_register == cpu_struct->idex_latch[0].source_register1) || 
                (cpu_struct->exmem_latch[0].destination_register == cpu_struct->idex_latch[0].source_register2)) {
                cpu_struct->ifid_latch[0].valid = 0;
                cpu_struct->ifid_latch[1].valid = 0;
                cpu_struct->idex_latch[0].valid = 0;
                cpu_struct->reg.program_counter = cpu_struct->exmem_latch[0].next_pc;
            }
        } else if (cpu_struct->data_hazard_detected == 1) { // forward
            if (cpu_struct->exmem_latch[0].destination_register == cpu_struct->idex_latch[0].source_register1) {
                cpu_struct->forwarding_unit[0] = 0b10;
            }
            if (cpu_struct->exmem_latch[0].destination_register == cpu_struct->idex_latch[0].source_register2) {
                cpu_struct->forwarding_unit[1] = 0b10;
            }
        }
    }

    // MEMWB hazard
    if (cpu_struct->memwb_latch[0].destination_register != 0 && cpu_struct->memwb_latch[0].control.reg_write) {
        if (cpu_struct->data_hazard_detected == 0) { // wait
            if ((cpu_struct->exmem_latch[0].destination_register != cpu_struct->idex_latch[0].source_register2 && 
                 cpu_struct->memwb_latch[0].destination_register == cpu_struct->idex_latch[0].source_register2) || 
                (cpu_struct->exmem_latch[0].destination_register != cpu_struct->idex_latch[0].source_register1 && 
                 cpu_struct->memwb_latch[0].destination_register == cpu_struct->idex_latch[0].source_register1)) {
                
                cpu_struct->ifid_latch[0].valid = 0;
                cpu_struct->ifid_latch[1].valid = 0;
                cpu_struct->idex_latch[0].valid = 0;
                cpu_struct->reg.program_counter = cpu_struct->exmem_latch[0].next_pc;
            }
        } else if (cpu_struct->data_hazard_detected == 1) { // forward
            if (cpu_struct->exmem_latch[0].destination_register != cpu_struct->idex_latch[0].source_register1 && 
                cpu_struct->memwb_latch[0].destination_register == cpu_struct->idex_latch[0].source_register1) {
                cpu_struct->forwarding_unit[0] = 0b01;
            }
            if (cpu_struct->exmem_latch[0].destination_register != cpu_struct->idex_latch[0].source_register2 && 
                cpu_struct->memwb_latch[0].destination_register == cpu_struct->idex_latch[0].source_register2) {
                cpu_struct->forwarding_unit[1] = 0b01;
            }
        }
    }
}

void latch_update(CPU_Struct* cpu_struct) {
    memcpy(&(cpu_struct->ifid_latch[1]), &(cpu_struct->ifid_latch[0]), sizeof(IFID_Latch));
    memcpy(&(cpu_struct->idex_latch[1]), &(cpu_struct->idex_latch[0]), sizeof(IDEX_Latch));
    memcpy(&(cpu_struct->exmem_latch[1]), &(cpu_struct->exmem_latch[0]), sizeof(EXMEM_Latch));
    memcpy(&(cpu_struct->memwb_latch[1]), &(cpu_struct->memwb_latch[0]), sizeof(MEMWB_Latch));

    memset(&(cpu_struct->ifid_latch[0]), 0, sizeof(IFID_Latch));
    memset(&(cpu_struct->idex_latch[0]), 0, sizeof(IDEX_Latch));
    memset(&(cpu_struct->exmem_latch[0]), 0, sizeof(EXMEM_Latch));
    memset(&(cpu_struct->memwb_latch[0]), 0, sizeof(MEMWB_Latch));
}

void branch_wait(CPU_Struct* cpu_struct, unsigned int branch_taken, unsigned int addr) {
    if (cpu_struct->idex_latch[1].control.branch) {
        cpu_struct->ifid_latch[0] = cpu_struct->ifid_latch[1];
        cpu_struct->idex_latch[0].valid = 0;

        if (branch_taken) {
            cpu_struct->reg.program_counter = addr;
        }
        else {
            cpu_struct->reg.program_counter = cpu_struct->ifid_latch[1].next_pc - 4;
        }
    }
}

void prediction_and_execution(CPU_Struct* cpu_struct, unsigned int branch_taken, unsigned int addr) {
    switch (cpu_struct->control_hazard_detected) {
        case 0:
            branch_wait(cpu_struct, branch_taken, addr);
            break;
        case 1:
            if (branch_taken) {
                cpu_struct->ifid_latch[0].valid = 0;
                cpu_struct->ifid_latch[1].valid = 0;
                cpu_struct->idex_latch[0].valid = 0;
            }
            cpu_struct->reg.program_counter = addr;
            break;
        case 2:
            if (cpu_struct->idex_latch[1].branch_history_found == 1) {
                if (!branch_taken) {
                    cpu_struct->reg.program_counter = cpu_struct->idex_latch[1].next_pc;
                    cpu_struct->ifid_latch[0].valid = 0;
                    cpu_struct->ifid_latch[1].valid = 0;
                    cpu_struct->idex_latch[0].valid = 0;
                }
            } else {
                if (branch_taken) {
                    cpu_struct->branch_history_unit[cpu_struct->idex_latch[1].branch_history_index].branch_instruction_address = cpu_struct->idex_latch[1].next_pc - 4;
                    cpu_struct->reg.program_counter = addr;
                    cpu_struct->branch_history_unit[cpu_struct->idex_latch[1].branch_history_index].branch_target_address = cpu_struct->reg.program_counter;
                    cpu_struct->ifid_latch[0].valid = 0;
                    cpu_struct->ifid_latch[1].valid = 0;
                    cpu_struct->idex_latch[0].valid = 0;
                }
            }
            break;
        case 3:
            if (cpu_struct->idex_latch[1].branch_history_found) {
                if (cpu_struct->idex_latch[1].pre_taken) {
                    if (branch_taken) {
                        cpu_struct->branch_history_unit[cpu_struct->idex_latch[1].branch_history_index].prediction_bit = 1;
                    } else {
                        cpu_struct->branch_history_unit[cpu_struct->idex_latch[1].branch_history_index].prediction_bit = 0;
                        cpu_struct->reg.program_counter = cpu_struct->idex_latch[1].next_pc;
                        cpu_struct->ifid_latch[0].valid = 0;
                        cpu_struct->ifid_latch[1].valid = 0;
                        cpu_struct->idex_latch[0].valid = 0;
                    }
                } else {
                    if (branch_taken) {
                        cpu_struct->branch_history_unit[cpu_struct->idex_latch[1].branch_history_index].prediction_bit = 1;
                        cpu_struct->reg.program_counter = cpu_struct->branch_history_unit[cpu_struct->idex_latch[1].branch_history_index].branch_target_address;
                        cpu_struct->ifid_latch[0].valid = 0;
                        cpu_struct->ifid_latch[1].valid = 0;
                        cpu_struct->idex_latch[0].valid = 0;
                    } else {
                        cpu_struct->branch_history_unit[cpu_struct->idex_latch[1].branch_history_index].prediction_bit = 0;
                    }
                }
            } else {
                if (branch_taken) {
                    cpu_struct->branch_history_unit[cpu_struct->idex_latch[1].branch_history_index].branch_instruction_address = cpu_struct->idex_latch[1].next_pc - 4;
                    cpu_struct->reg.program_counter = addr;
                    cpu_struct->branch_history_unit[cpu_struct->idex_latch[1].branch_history_index].branch_target_address = cpu_struct->reg.program_counter;
                    cpu_struct->branch_history_unit[cpu_struct->idex_latch[1].branch_history_index].prediction_bit = 1;
                    cpu_struct->ifid_latch[0].valid = 0;
                    cpu_struct->ifid_latch[1].valid = 0;
                    cpu_struct->idex_latch[0].valid = 0;
                }
            }
            break;
        default:
            break;
    }
}

void reg_file_ops(Register_Struct* reg, unsigned int* mux_out) {
    reg->register_file.read_data1 = reg->general_purpose_reg[*(reg->register_file.read_reg1)];
    reg->register_file.read_data2 = reg->general_purpose_reg[*(reg->register_file.read_reg2)];
    reg->register_file.write_reg = mux_out;
}

void reg_file_write(Register_Struct* reg, unsigned int write_reg, unsigned int write_data, unsigned int enable) {
    if ((write_reg > 0) && (enable == 1)) {
        reg->general_purpose_reg[write_reg] = write_data;
    }
}

void alu_ctrl_ops(ALU_Control_Unit* acu) {
    *(acu->jr) = 0;

    switch (*(acu->alu_op)) {
        case 0:
            acu->alu_control = ALU_ADD;
            break;
        case 1:
            acu->alu_control = ALU_SUB;
            break;
        case 2:
            acu->alu_control = ALU_AND;
            break;
        case 3:
            acu->alu_control = ALU_OR;
            break;
        case 4:
            acu->alu_control = ALU_XOR;
            break;
        case 5:
            acu->alu_control = ALU_SLT;
            break;
        case 6:
            switch (*(acu->function_code)) {
                case ADDITION:
                case ADDITION_UNSIGNED:
                    acu->alu_control = ALU_ADD;
                    break;
                case JUMP_REGISTER:
                    acu->alu_control = ALU_ADD;
                    *(acu->jr) = 1;
                    break;
                case JUMP_AND_LINK_REGISTER:
                    acu->alu_control = ALU_ADD;
                    *(acu->jal) = 1;
                    break;
                case SUBTRACTION:
                case SUBTRACTION_UNSIGNED:
                    acu->alu_control = ALU_SUB;
                    break;
                case AND_OPERATION:
                    acu->alu_control = ALU_AND;
                    break;
                case OR_OPERATION:
                    acu->alu_control = ALU_OR;
                    break;
                case XOR_OPERATION:
                    acu->alu_control = ALU_XOR;
                    break;
                case NOR_OPERATION:
                    acu->alu_control = ALU_NOR;
                    break;
                case SET_LESS_THAN:
                case SET_LESS_THAN_UNSIGNED:
                    acu->alu_control = ALU_SLT;
                    break;
                case SHIFT_LEFT_LOGICAL:
                    acu->alu_control = ALU_SLL;
                    break;
                case SHIFT_RIGHT_LOGICAL:
                    acu->alu_control = ALU_SRL;
                    break;
                case SHIFT_RIGHT_ARITHMETIC:
                    acu->alu_control = ALU_SRA;
                    break;
                case SHIFT_LEFT_LOGICAL_VAR:
                    acu->alu_control = ALU_SLLV;
                    break;
                case SHIFT_RIGHT_LOGICAL_VAR:
                    acu->alu_control = ALU_SRLV;
                    break;
                case SHIFT_RIGHT_ARITHMETIC_VAR:
                    acu->alu_control = ALU_SRAV;
                    break;
            }
            break;
        case 7:
            // j, jal
            break;
        default:
            break;
    }
}

void alu_ops(ALU_Struct* alu_struct, unsigned int* mux_out) {
    alu_struct->input2 = mux_out;

    alu_struct->input2_mux[0] = *(alu_struct->input2);
    alu_struct->input2_mux[1] = ~(*(alu_struct->input2));

    int input2_mux_out = alu_struct->input2_mux[((*(alu_struct->alu_control) >> 4) & 1)];
    int sum = (*(alu_struct->input1)) + input2_mux_out + ((*(alu_struct->alu_control) >> 4) & 1);
    int slt = (sum >> 31) & 1;

    // shift
    alu_struct->shift_amount_mux[1] = *(alu_struct->input2);
    alu_struct->shift_amount_mux[0] = *(alu_struct->shift_amount);

    int shamt_mux_out = alu_struct->shift_amount_mux[((*(alu_struct->alu_control) >> 5) & 1)];
    int srl = input2_mux_out >> shamt_mux_out;
    int sll = input2_mux_out << shamt_mux_out;
    int sra = (int)input2_mux_out >> shamt_mux_out;

    alu_struct->out_mux[5] = (*(alu_struct->input1)) ^ input2_mux_out;
    alu_struct->out_mux[6] = ~((*(alu_struct->input1)) | input2_mux_out);
    alu_struct->out_mux[0] = (*(alu_struct->input1)) & input2_mux_out;
    alu_struct->out_mux[1] = (*(alu_struct->input1)) | input2_mux_out;
    alu_struct->out_mux[2] = sum;
    alu_struct->out_mux[3] = slt;
    alu_struct->out_mux[4] = sll;
    alu_struct->out_mux[7] = srl;
    alu_struct->out_mux[8] = sra;

    alu_struct->result = alu_struct->out_mux[*(alu_struct->alu_control) & 0x7];

    alu_struct->alu_flags.zero = !(alu_struct->result);
    alu_struct->alu_flags.negative = ((alu_struct->result >> 31) & 1);
    alu_struct->alu_flags.greater_than_zero = !(alu_struct->alu_flags.negative || alu_struct->alu_flags.zero); // result > 0
    alu_struct->alu_flags.less_equal_zero = alu_struct->alu_flags.zero || alu_struct->alu_flags.negative; // result <= 0
}

void control_unit_ops(Control_Unit* cu, int opcode) {
    
    cu->reg_dst = (opcode == INSTRUCTION_TYPE_R) ? 1 : (opcode == JUMP_AND_LINK) ? 2 : 0;

    cu->reg_write = ((opcode == INSTRUCTION_TYPE_R) || (opcode == JUMP_AND_LINK)) || 
                    ((opcode & 0x38) == 0x20) || ((opcode & 0x38) == 0x08);

    cu->jump = (opcode == JUMP) || (opcode == JUMP_AND_LINK);

    cu->jal = (opcode == JUMP_AND_LINK);

    cu->mem_write = ((opcode & 0x38) == 0x28) ? 1 : 0; // sw, sh, sb

    cu->mem_to_reg = ((opcode & 0x38) == 0x20) ? 1 : 0; // lw, lb(u), lh(u)

    cu->branch = (opcode & 0x3c) == 0x4;

    cu->extra = (opcode & 0x07);


    if ((opcode & 0x3c) == 0x4 || opcode == INSTRUCTION_TYPE_R) { // branch or R
        cu->alu_src = 0; // read data2 == read register2
    } else if ((opcode & 0x3c) == 0x8 || (opcode & 0x30) == 0x20) { // load, store, arithmetic
        cu->alu_src = 1; // read data2 == imm with sign ext
    } else if ((opcode & 0x3c) == 0xc) {
        cu->alu_src = 2; // read data2 == imm with zero ext
    } else if (opcode == LOAD_UPPER_IMMEDIATE) { // LUI
        cu->alu_src = 3; // read data2 == imm with sll 16
    }

    // alu_op
    if ((opcode & 0x30) == 0x20 || (opcode & 0x3e) == 0x08 || opcode == LOAD_UPPER_IMMEDIATE) {
        cu->alu_op = 0b000;
    } else if ((opcode & 0x3c) == 0x04) { // Branch
        cu->alu_op = 0b001;
    } else if (opcode == AND_IMMEDIATE) {
        cu->alu_op = 0b010;
    } else if (opcode == OR_IMMEDIATE) {
        cu->alu_op = 0b011;
    } else if (opcode == XOR_IMMEDIATE) {
        cu->alu_op = 0b100;
    } else if ((opcode & 0x3e) == 0x0a) {
        cu->alu_op = 0b101;
    } else if (opcode == INSTRUCTION_TYPE_R) {
        cu->alu_op = 0b110;
    } else if (opcode == JUMP || opcode == JUMP_AND_LINK) {
        cu->alu_op = 0b111; // special alu_op
    } else {
        // error
    }
}

void print_cycle(CPU_Struct* cpu_struct) {
    printf("\nCycle[%d] (PC: 0x%x)\n", ++cycle_count, cpu_struct->reg.program_counter);
}

void print_fetch(CPU_Struct* cpu_struct, int tmp_pc) {
    printf(" [IF]\n");
    printf("\t0x%08x\t pc: 0x%x\n", cpu_struct->ifid_latch[0].data, tmp_pc);
    printf("\t[PC update] pc <- 0x%x\n", cpu_struct->ifid_latch[0].next_pc);
}

void print_decode(CPU_Struct* cpu_struct) {
    printf(" [ID] \n");
    if (cpu_struct->idex_latch[0].valid) {
        if (cpu_struct->ifid_latch[1].data == 0) {
            printf("\tNop\n");
        }
        else if (cpu_struct->idex_latch[0].opcode == INSTRUCTION_TYPE_R) {
            printf("\ttype: R, ");
            printf("opcode: 0x%x, ", cpu_struct->idex_latch[0].opcode);
            printf("rs: 0x%x (R[%d]=0x%x), ", cpu_struct->idex_latch[0].source_register1, cpu_struct->idex_latch[0].source_register1, cpu_struct->reg.general_purpose_reg[cpu_struct->idex_latch[0].source_register1]);
            printf("rt: 0x%x (R[%d]=0x%x), ", cpu_struct->idex_latch[0].source_register2, cpu_struct->idex_latch[0].source_register2, cpu_struct->reg.general_purpose_reg[cpu_struct->idex_latch[0].source_register2]);
            printf("rd: 0x%x (%d), ", cpu_struct->idex_latch[0].destination_register, cpu_struct->idex_latch[0].destination_register);
            printf("shamt: 0x%x, ", cpu_struct->idex_latch[0].shift_amount);
            printf("funct: 0x%x\n", cpu_struct->idex_latch[0].function);
            R_instruction_count++;
        }
        else if (cpu_struct->idex_latch[0].opcode == JUMP || cpu_struct->idex_latch[0].opcode == JUMP_AND_LINK) {
            printf("\ttype: J, ");
            printf("opcode: 0x%x, ", cpu_struct->idex_latch[0].opcode);
            printf("address: 0x%x\n", cpu_struct->idex_latch[0].address);
            J_instruction_count++;
        }
        else {
            printf("\ttype: I, ");
            printf("opcode: 0x%x, ", cpu_struct->idex_latch[0].opcode);
            printf("rs: 0x%x (R[%d]=0x%x), ", cpu_struct->idex_latch[0].source_register1, cpu_struct->idex_latch[0].source_register1, cpu_struct->reg.general_purpose_reg[cpu_struct->idex_latch[0].source_register1]);
            printf("rt: 0x%x (R[%d]=0x%x), ", cpu_struct->idex_latch[0].source_register2, cpu_struct->idex_latch[0].source_register2, cpu_struct->reg.general_purpose_reg[cpu_struct->idex_latch[0].source_register2]);
            printf("imm: 0x%x\n", cpu_struct->idex_latch[0].immediate_value);
            I_instruction_count++;
        }

        if (cpu_struct->idex_latch[0].control.jump) {
            printf("\t[PC update (jump)] pc <- 0x%x\n", cpu_struct->reg.program_counter);
        }
    }
    else {
        printf("\t[ Stall ]\n");
        stall_count++;
    }
}

void print_execute(CPU_Struct* cpu_struct) {
    printf(" [EXE] \n");
    if (cpu_struct->exmem_latch[0].valid) {
        if (cpu_struct->idex_latch[1].control.alu_src == 0) {
            printf("\trs: %x(r[%d]=%x), rt: %x(r[%d]=%x), alu_struct result : %x\n", cpu_struct->idex_latch[1].source_register1, cpu_struct->idex_latch[1].source_register1, cpu_struct->exmem_latch[0].read_data1, cpu_struct->idex_latch[1].source_register2, cpu_struct->idex_latch[1].source_register2, cpu_struct->exmem_latch[0].read_data2, cpu_struct->exmem_latch[0].alu_result);
        }
        else {
            printf("\trs: %x(r[%d]=%x), imm: %x, alu_struct result : %x\n", cpu_struct->idex_latch[1].source_register1, cpu_struct->idex_latch[1].source_register1, cpu_struct->exmem_latch[0].read_data1, cpu_struct->exmem_latch[0].read_data2, cpu_struct->exmem_latch[0].alu_result);
        }

        if (cpu_struct->idex_latch[1].control.jr) {
            printf("\t[PC update (jump register)] pc <- 0x%x\n", cpu_struct->reg.program_counter);
        }
        if (cpu_struct->idex_latch[1].control.branch) {
            printf("\tbranch target : 0x%08x\n", cpu_struct->exmem_latch[0].branch_target);
        }
        if (cpu_struct->exmem_latch[0].control.branch ? cpu_struct->mux_branch[cpu_struct->exmem_latch[0].control.extra & 0x3] : 0) {
            printf("\t[PC update (branch)] pc <- 0x%x\n", cpu_struct->reg.program_counter);
            branch_count++;
        }
    }
    else {
        printf("\t[ STALL ]\n");
        stall_count++;
    }
}

void print_memory(CPU_Struct* cpu_struct) {
    printf(" [MEM] \n");
    if (cpu_struct->exmem_latch[1].valid) {
        if (cpu_struct->exmem_latch[1].control.mem_write) {
            printf("\t[STORE] M[0x%08x]  <- %x\n", cpu_struct->exmem_latch[1].alu_result, cpu_struct->exmem_latch[1].read_data2);
            memory_instruction_count++;
        }
        if (cpu_struct->exmem_latch[1].control.mem_to_reg) {
            printf("\t[MEMORY ACCESS] read_data <- M[0x%08x] = %x\n", cpu_struct->exmem_latch[1].alu_result, cpu_struct->memwb_latch[0].read_data);
            memory_instruction_count++;
        }
    }
    else {
        printf("\t[ STALL ]\n");
        stall_count++;
    }
}

void print_write_back(CPU_Struct* cpu_struct) {
    printf(" [WB] \n");
    if (cpu_struct->memwb_latch[1].valid) {
        if (cpu_struct->memwb_latch[1].control.reg_write) {
            printf("\tr[%d] <- %x\n", cpu_struct->memwb_latch[1].destination_register, cpu_struct->mux_member_PC[cpu_struct->memwb_latch[1].control.jal]);
        }
    }
    else {
        printf("\t[ STALL ]\n");
        stall_count++;
    }
}

void print_fwd(CPU_Struct* cpu_struct) {
    printf(" [Forwarding] \n");
    if (cpu_struct->forwarding_unit[0] == 0b10) {
        printf("\trs<-[EXMEM Forwarding]\n");
    }
    else if (cpu_struct->forwarding_unit[0] == 0b01) {
        printf("\trs<-[MEMWB Forwarding]\n");
    }

    if (cpu_struct->forwarding_unit[1] == 0b10) {
        printf("\trt<-[EXMEM Forwarding]\n");
    }
    else if (cpu_struct->forwarding_unit[1] == 0b01) {
        printf("\trt<-[MEMWB Forwarding]\n");
    }
}

void print_results(CPU_Struct* cpu_struct) {
    printf("\n===========================PROGRAM RESULT=============================\n");
    printf("Return value (R[2]) :\t\t\t%d\n", cpu_struct->reg.general_purpose_reg[2]);
    printf("Total Cycle :\t\t\t\t%d\n", cycle_count);
    printf("Executed 'R' instruction :\t\t%d\n", R_instruction_count);
    printf("Executed 'I' instruction :\t\t%d\n", I_instruction_count);
    printf("Executed 'J' instruction :\t\t%d\n", J_instruction_count);
    printf("Number of Branch Taken :\t\t%d\n", branch_count);
    printf("Number of Memory Access Instruction :\t%d\n", memory_instruction_count);
    printf("Number of STALL :\t\t\t%d\n", stall_count);
    printf("======================================================================\n");
    return;
}
