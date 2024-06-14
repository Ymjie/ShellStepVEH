#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

unsigned char dynamic_xor_key = 0x1C;
unsigned char* shellcode;
unsigned char* original_shellcode;
SIZE_T shellcodeSize;
DWORD previousEip = 0;
//int innum = 0;
//int outnum = 0;
bool ischangeEIP = false;
bool* changeOffset;
bool in = false;
DWORD mypreviousEip;
DWORD shellcode_start;
DWORD shellcode_end;
DWORD EIPoffset;
MEMORY_BASIC_INFORMATION mbi;
bool debug = false;
EXCEPTION_POINTERS* myExceptionInfo;
DWORD oldProtect;
bool isxor = false;
void saveShellcodeToFile(const char* filename, unsigned char* shellcode, SIZE_T shellcodeSize) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    SIZE_T written = fwrite(shellcode, 1, shellcodeSize, file);
    if (written != shellcodeSize) {
        perror("Error writing to file");
    }
    else {
        printf("Shellcode written to file successfully.\n");
    }

    fclose(file);
}

void encprocent() {
    double percentage;
    int a = 0;
    for (size_t i = 0; i < shellcodeSize; i++) {
        if (changeOffset[i]) {
            a++;
        }
    }
    percentage = ((double)a / (double)shellcodeSize) * 100;
    printf("Percentage: %.2f%%\n", percentage);
}
//void printShellcode() {
//    printf("Shellcode (size: %zu):\n", shellcodeSize);
//    for (size_t i = 0; i < shellcodeSize; i++) {
//        if (isxor && encryptOffset[i]) {
//            printf("\\x%02x", shellcode[i] ^ dynamic_xor_key);
//        }
//        else {
//            printf("\\x%02x", shellcode[i]);
//        }
//
//        if ((i + 1) % 16 == 0) { // 每16个字节换行
//            printf("\n");
//        }
//    }
//    printf("\n");
//}
// 定义操作类型
typedef enum {
    ENCRYPT,
    DECRYPT,
    MEMAddr,
    SHELLCODE
} OperationType;


void operateShellcode(OperationType operation, OperationType type, uint32_t addr) {
    //printf("addr:%x\n", addr);
    if (!isxor) {
        return;
    }
    size_t length =15;
    if (type == MEMAddr) {
        length = 4;
    }
    uint32_t offset = addr - shellcode_start;
    if (addr >= shellcode_start && addr <= shellcode_end) {
        for (SIZE_T i = 0; i < length; ++i) {
            if (shellcodeSize -(offset +i) > 0) {
                if (!changeOffset[offset+i]) {
                    if (shellcode[offset+i]==original_shellcode[offset+i]) {
                        if (operation == DECRYPT) {
                            shellcode[offset+i] ^=dynamic_xor_key;
                        }
                        continue;
                    }
                    if (shellcode[offset+i] == (original_shellcode[offset+i]^dynamic_xor_key)) {
                        if (operation == ENCRYPT) {
                            shellcode[offset+i] = original_shellcode[offset+i];
                        }
                        continue;
                    }
                    changeOffset[offset+i] = true;
                    printf("EIP:%x,Old:%x New:%x\n",previousEip, original_shellcode[offset + i] ^ dynamic_xor_key, shellcode[offset+i]);
                }
            }
        }
    }
}
typedef struct {
    uint32_t eax;
    uint32_t ecx;
    uint32_t edx;
    uint32_t ebx;
    uint32_t esp;
    uint32_t ebp;
    uint32_t esi;
    uint32_t edi;
    uint32_t eip; // eip 通常不在 ModR/M 中使用，但保留在结构体中以保持一致性
} Registers;

// 模拟的寄存器实例
Registers regs = { 0 };

// 内存读取函数
int read_memory(uint32_t address, uint32_t* value) {
    SIZE_T bytesRead;

    // 尝试读取内存
    if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)address, value, sizeof(*value), &bytesRead) && bytesRead == sizeof(*value)) {
        return 1; // 成功读取内存
    }
    else {
        //printf("Failed to read memory at address 0x%08X\n", address);
        return 0; // 内存读取失败
    }
}
void parse_modrm(uint8_t modrm, uint8_t* mod, uint8_t* reg, uint8_t* rm) {
    *mod = (modrm >> 6) & 0x03;
    *reg = (modrm >> 3) & 0x07;
    *rm = modrm & 0x07;
}

void parse_sib(uint8_t sib, uint8_t* scale, uint8_t* index, uint8_t* base) {
    *scale = (sib >> 6) & 0x03;
    *index = (sib >> 3) & 0x07;
    *base = sib & 0x07;
}

uint32_t get_register_value(uint8_t reg, Registers* regs) {
    switch (reg) {
    case 0: return regs->eax;
    case 1: return regs->ecx;
    case 2: return regs->edx;
    case 3: return regs->ebx;
    case 4: return regs->esp;
    case 5: return regs->ebp;
    case 6: return regs->esi;
    case 7: return regs->edi;
    default: return 0; // 无效寄存器编号
    }
}
uint32_t calculate_memory_address(uint8_t* opcode, int* offset, uint8_t mod, uint8_t rm, Registers* regs, uint8_t has_sib, uint8_t scale, uint8_t index, uint8_t base) {
    uint32_t address = 0;

    switch (mod) {
    case 0:
        if (has_sib) {
            address = get_register_value(base, regs) + (get_register_value(index, regs) << scale);
            if (base == 5) {
                uint32_t disp;
                if (!read_memory(*(uint32_t*)(opcode + *offset), &disp)) {
                    return 0; // 读取失败
                }
                address += disp;
                *offset += 4;
            }
        }
        else if (rm == 5) {
            uint32_t disp;
            if (!read_memory(*(uint32_t*)(opcode + *offset), &disp)) {
                return 0; // 读取失败
            }
            address = disp;
            *offset += 4;
        }
        else {
            address = get_register_value(rm, regs);
        }
        break;
    case 1:
        if (has_sib) {
            address = get_register_value(base, regs) + (get_register_value(index, regs) << scale) + (int8_t)opcode[*offset];
        }
        else {
            address = get_register_value(rm, regs) + (int8_t)opcode[*offset];
        }
        *offset += 1;
        break;
    case 2:
        if (has_sib) {
            uint32_t disp;
            if (!read_memory(*(uint32_t*)(opcode + *offset), &disp)) {
                return 0; // 读取失败
            }
            address = get_register_value(base, regs) + (get_register_value(index, regs) << scale) + disp;
        }
        else {
            uint32_t disp;
            if (!read_memory(*(uint32_t*)(opcode + *offset), &disp)) {
                return 0; // 读取失败
            }
            address = get_register_value(rm, regs) + disp;
        }
        *offset += 4;
        break;
    case 3:
        // Register-direct addressing, no memory address used.
        return 0;
    }
    return address;
}

uint32_t analyze_instruction(uint8_t* opcode, Registers* regs) {
    uint8_t mod = 0, reg = 0, rm = 0, scale = 0, index = 0, base = 0;
    uint32_t address = 0;
    int offset = 0;
    uint8_t has_sib = 0;

    // 处理前缀字节
    while (opcode[offset] == 0xF0 || opcode[offset] == 0xF2 || opcode[offset] == 0xF3 || // 锁前缀和重复前缀
        opcode[offset] == 0x2E || opcode[offset] == 0x36 || opcode[offset] == 0x3E || // 段前缀
        opcode[offset] == 0x26 || opcode[offset] == 0x64 || opcode[offset] == 0x65 || // 段前缀
        opcode[offset] == 0x66 || opcode[offset] == 0x67) { // 操作数大小和地址大小前缀
        offset++;
    }

    // 获取操作码
    uint8_t primary_opcode = opcode[offset++];

    if (primary_opcode == 0xF3 && opcode[offset] == 0xA4) {
        // 处理 REP MOVSB 指令
        uint32_t src_address = get_register_value(6, regs); // ESI 寄存器
        uint32_t dest_address = get_register_value(7, regs); // EDI 寄存器
        uint32_t count = get_register_value(1, regs); // ECX 寄存器
        return src_address; // 或者其他需要的返回信息
    }

    if (primary_opcode == 0xA4) {
        // 处理 MOVSB 指令
        uint32_t src_address = get_register_value(6, regs); // ESI 寄存器
        uint32_t dest_address = get_register_value(7, regs); // EDI 寄存器
        return src_address; // 或者其他需要的返回信息
    }

    // 处理其他字符串指令
    if (primary_opcode == 0xA5 || primary_opcode == 0xAA || primary_opcode == 0xAB ||
        primary_opcode == 0xAC || primary_opcode == 0xAD || primary_opcode == 0xAE ||
        primary_opcode == 0xAF || primary_opcode == 0xA6 || primary_opcode == 0xA7) {
        // 这里可以添加更多字符串指令的处理逻辑
        return get_register_value(6, regs); // 根据需要返回合适的地址或信息
    }
    if (primary_opcode == 0x0F) {
        // 处理两字节操作码
        uint8_t secondary_opcode = opcode[offset++];

        switch (secondary_opcode) {
        case 0xB6: // MOVZX r16, r/m8
        case 0xB7: // MOVZX r32, r/m16
        case 0xBE: // MOVSX r16, r/m8
        case 0xBF: // MOVSX r32, r/m16
        case 0xAF: // IMUL r32, r/m32
        case 0xA3: // BT r/m32, r32
        case 0xAB: // BTS r/m32, r32
        case 0xB3: // BTR r/m32, r32
        case 0xBB: // BTC r/m32, r32
        case 0xC0: // XADD r/m8, r8
        case 0xC1: // XADD r/m32, r32
        {
            uint8_t modrm_byte = opcode[offset++];
            parse_modrm(modrm_byte, &mod, &reg, &rm);

            if (rm == 4 && mod != 3) {  // SIB byte is present
                uint8_t sib_byte = opcode[offset++];
                parse_sib(sib_byte, &scale, &index, &base);
                has_sib = 1;
            }

            address = calculate_memory_address(opcode, &offset, mod, rm, regs, has_sib, scale, index, base);
            return address;
        }
        default:
            return 0; // 不支持的两字节操作码
        }
    }
    else if ((primary_opcode & 0xFC) == 0x80 ||   // 80-83 二进制操作（带 ModR/M）
        (primary_opcode & 0xF0) == 0x00 ||   // 00-0F 一些常见操作（带 ModR/M）
        (primary_opcode & 0xF0) == 0x20 ||   // 20-2F 一些常见操作（带 ModR/M）
        (primary_opcode & 0xF0) == 0x30 ||   // 30-3F 一些常见操作（带 ModR/M）
        (primary_opcode & 0xF0) == 0x60 ||   // 60-6F 一些常见操作（带 ModR/M）
        (primary_opcode & 0xF0) == 0x70 ||   // 70-7F 一些常见跳转（带 ModR/M）
        (primary_opcode & 0xF8) == 0xC0 ||   // C0-C1, C6-C7 操作
        (primary_opcode & 0xFE) == 0xD0 ||   // D0-D3 操作
        (primary_opcode & 0xF8) == 0xF6 ||   // F6-F7 操作
        (primary_opcode >= 0x40 && primary_opcode <= 0x5F) || // 40-5F inc/dec和其他操作
        (primary_opcode & 0xF8) == 0xD8 ||   // D8-DF 浮点运算
        (primary_opcode & 0xF8) == 0xE0 ||   // E0-E3 循环控制
        (primary_opcode & 0xFC) == 0xF0 ||   // F0-F3 预取前缀或锁前缀（带 ModR/M）
        (primary_opcode & 0xFE) == 0x88 ||   // 88-8B 移动（带 ModR/M）
        (primary_opcode & 0xFC) == 0xA0 ||   // A0-A3 移动和其他操作（带 ModR/M）
        (primary_opcode & 0xFC) == 0xB0 ||   // B0-B7 移动（带 ModR/M）
        (primary_opcode & 0xF0) == 0x50) {   // 50-5F 推和弹（带 ModR/M）
        // 需要解析 ModR/M 字节

        uint8_t modrm_byte = opcode[offset++];
        parse_modrm(modrm_byte, &mod, &reg, &rm);

        if (rm == 4 && mod != 3) {  // SIB byte is present
            uint8_t sib_byte = opcode[offset++];
            parse_sib(sib_byte, &scale, &index, &base);
            has_sib = 1;
        }

        address = calculate_memory_address(opcode, &offset, mod, rm, regs, has_sib, scale, index, base);
        return address;
    }
    return 0; // Instruction does not involve memory address computation.
}
void operateOPMEMADDR() {
    BYTE* eipPtr = reinterpret_cast<BYTE*>(previousEip);
    BYTE bytes[15];
    if (in && isxor) {
        for (int i = 0; i < 15; ++i) {
            if (previousEip + i <= shellcode_end) {
                bytes[i] = *(eipPtr + i);
            }
        }

        regs.eax = myExceptionInfo->ContextRecord->Eax;
        regs.ebx = myExceptionInfo->ContextRecord->Ebx;
        regs.ecx = myExceptionInfo->ContextRecord->Ecx;
        regs.edx = myExceptionInfo->ContextRecord->Edx;
        regs.esi = myExceptionInfo->ContextRecord->Esi;
        regs.edi = myExceptionInfo->ContextRecord->Edi;
        regs.ebp = myExceptionInfo->ContextRecord->Ebp;
        regs.esp = myExceptionInfo->ContextRecord->Esp;
        regs.eip = myExceptionInfo->ContextRecord->Eip;
        DWORD OPMEMaddr = (DWORD)analyze_instruction(bytes, &regs);
        if (OPMEMaddr) {
            //printf("[in] The memory address to be accessed by the next assembly instruction is:%x\n", OPMEMaddr);
            if (OPMEMaddr >= shellcode_start && OPMEMaddr <= shellcode_end) {
                //printf("[in] EIP:%x OPMENADDR:%x\n", eipPtr, OPMEMaddr);
                operateShellcode(DECRYPT, MEMAddr, OPMEMaddr);
            }
            else {

            }
        }
    }

}
BYTE c1 =0;
LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    myExceptionInfo = ExceptionInfo;
    mypreviousEip = previousEip;
    previousEip = ExceptionInfo->ContextRecord->Eip;
    shellcode_start = (DWORD)shellcode;
    shellcode_end = shellcode_start + shellcodeSize;
    EIPoffset = ExceptionInfo->ContextRecord->Eip - shellcode_start;
    in = ExceptionInfo->ContextRecord->Eip >= shellcode_start && ExceptionInfo->ContextRecord->Eip <= shellcode_end;
    //if (debug) {
    //    printf("EIP -> %x\n", previousEip);
    //}
    SIZE_T result = VirtualQuery(shellcode, &mbi, sizeof(mbi));
    if (mbi.Protect != PAGE_NOACCESS) {
        operateShellcode(ENCRYPT, SHELLCODE,mypreviousEip);
        if (in) {
            operateShellcode(DECRYPT, SHELLCODE,previousEip);
        }
    }

    if (!(in && mbi.Protect == PAGE_NOACCESS)) {
        operateOPMEMADDR();
    }
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
        DWORD_PTR faultingAddress = (DWORD_PTR)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        if (in) {
            printf("faultingAddress :%x\n", faultingAddress);
            printf("[Enter shellcode segment] EIP:%X offset:%x\n", previousEip, EIPoffset);
            encprocent();
            if (mbi.Protect == PAGE_NOACCESS) {
                //VirtualProtect(shellcode, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                printf("[%s]Modify the shellcode memory attribute to PAGE_EXECUTE_READWRITE\n", VirtualProtect(shellcode, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect) ? "+" : "-");
                operateShellcode(DECRYPT, SHELLCODE, previousEip);
                operateOPMEMADDR();
            }
            else {
                VirtualProtect(shellcode, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                //printf("[%s]Modify the shellcode memory attribute to PAGE_EXECUTE_READWRITE\n", VirtualProtect(shellcode, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect) ? "+" : "-");
            }
            ExceptionInfo->ContextRecord->EFlags |= 0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else if (faultingAddress >= shellcode_start && faultingAddress <= shellcode_end) {
            printf("External access to :%x\n", faultingAddress);
            //VirtualProtect(shellcode, shellcodeSize, PAGE_READWRITE, &oldProtect);
            printf("[%s]Modify the shellcode memory attribute to PAGE_READWRITE\n", VirtualProtect(shellcode, shellcodeSize, PAGE_READWRITE, &oldProtect) ? "+" : "-");
            //if (faultingAddress - shellcode_start == 0x1cc) {
            //    debug = true;
            //}
            operateShellcode(DECRYPT, MEMAddr,faultingAddress);
            //operateShellcode(DECRYPT, 0, shellcodeSize, dynamic_xor_key);
            ExceptionInfo->ContextRecord->EFlags |= 0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (in) {
            //innum++;
            //if (c1 != shellcode[0xf]) {
            //    printf("0xF :%x\npEIP:%x\n", shellcode[0xf], mypreviousEip);
            //    for (size_t i = 0; i < 15; i++)
            //    {
            //        printf("\\x%02x", shellcode[mypreviousEip-shellcode_start+i] ^ dynamic_xor_key);
            //    }
            //    printf("\n"); 
            //    printf("%x\n", ExceptionInfo->ContextRecord->Ebp-0x8);
            //    printf("ecx:%x\n", ExceptionInfo->ContextRecord->Ecx);
            //    char fileName[20];
            //    sprintf(fileName, "Out_%x.bin", previousEip);
            //    printf("[Exit shellcode segment] EIP:%x\n", previousEip);
            //    saveShellcodeToFile(fileName, shellcode, shellcodeSize);
            //    c1 = shellcode[0xf];
            //}
            ExceptionInfo->ContextRecord->EFlags |= 0x100;
        }
        else {
            //outnum++;
            if (mbi.Protect != PAGE_NOACCESS) {

                //VirtualProtect(shellcode, shellcodeSize, PAGE_NOACCESS, &oldProtect);
                printf("[%s]Modify the shellcode memory attribute to PAGE_NOACCESS\n", VirtualProtect(shellcode, shellcodeSize, PAGE_NOACCESS, &oldProtect) ? "+" : "-");
                encprocent();

            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_HEAP_CORRUPTION) {
        printf("Caught STATUS_HEAP_CORRUPTION exception!\n");
        printf("Exception Address: %p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
        printf("Exception Code: 0x%08x\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
        printf("Exception Record:\n");
        printf("  Number of Parameters: %lu\n", ExceptionInfo->ExceptionRecord->NumberParameters);
        for (ULONG i = 0; i < ExceptionInfo->ExceptionRecord->NumberParameters; i++) {
            printf("  Parameter[%lu]: 0x%p\n", i, (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[i]);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}



int HandleException(EXCEPTION_POINTERS* ExceptionInfo) {
    printf("Exception code: 0x%08X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
    printf("Exception address: 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
    return EXCEPTION_EXECUTE_HANDLER;
}
PVOID exceptionHandler = nullptr;
void Xor() {
    for (size_t i = 0; i < shellcodeSize; i++)
    {
        shellcode[i] ^= dynamic_xor_key;
    }
}
void main() {

    std::ifstream file("182558101486960647.bin", std::ios::binary); // 以二进制模式打开文件

    if (!file) {
        std::cerr << "无法打开文件" << std::endl;
    }
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
    file.close(); // 关闭文件

    unsigned char* shellcode_calc = new unsigned char[data.size()];
    std::copy(data.begin(), data.end(), shellcode_calc);
    shellcodeSize = data.size();
    shellcode = (unsigned char*)VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    original_shellcode = (unsigned char*)malloc(shellcodeSize);
    memcpy(shellcode, shellcode_calc, shellcodeSize);
    changeOffset = (bool*)malloc(shellcodeSize * sizeof(bool));
    memset(changeOffset, 0, shellcodeSize * sizeof(bool));
    if (isxor) {
        Xor();
    }
    memcpy(original_shellcode, shellcode, shellcodeSize);
    exceptionHandler = AddVectoredExceptionHandler(1, ExceptionHandler);
    void (*a)() = (void (*)())shellcode;
    a();
    //__try {
    //    a(); 
    //}
    //__except (HandleException(GetExceptionInformation())) {}
    // 释放资源
        // 解除异常处理程序
    if (exceptionHandler != nullptr) {
        RemoveVectoredExceptionHandler(exceptionHandler);
    }
    free(changeOffset);
    free(original_shellcode);
    VirtualFree(shellcode, 0, MEM_RELEASE);
}
//if (ischangeEIP) {
  //    ischangeEIP = false;
  //    for (SIZE_T i = 0; i < shellcodeSize; ++i) {
  //        if (shellcode[i] != original_shellcode[i]) {
  //            printf("previousEipOffset:%x  Shellcode fix offset: %x, original: 0x%02X, new: 0x%02X\n", mypreviousEip - shellcode_start, i, original_shellcode[i], shellcode[i]);
  //            original_shellcode[i] = shellcode[i];
  //        }
  //    }
  //}
  //else {
  //    for (SIZE_T i = 0; i < shellcodeSize; ++i) {
  //        if (shellcode[i] != original_shellcode[i]) {
  //            if (!(mypreviousEip >= shellcode_start && mypreviousEip < shellcode_end)) {
  //                printf("GGGG\n");
  //            }
  //            printf("previousEipOffset:%x  Shellcode modified at offset: %x, original: 0x%02X, new: 0x%02X\n", mypreviousEip - shellcode_start, i, original_shellcode[i], shellcode[i]);
  //            shellcode[i] = original_shellcode[i] ^ dynamic_xor_key;
  //            encryptOffset[i] = false;
  //            ischangeEIP = true;
  //            ExceptionInfo->ContextRecord->Eip = mypreviousEip;
  //            previousEip = mypreviousEip;
  //            EIPoffset = ExceptionInfo->ContextRecord->Eip - shellcode_start;
  //        }
  //    }
  //}
