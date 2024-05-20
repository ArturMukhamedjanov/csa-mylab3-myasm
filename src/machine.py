#!/usr/bin/python3
import logging
import sys

from isa import *

logger = logging.getLogger("machine_logger")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


class ALU:
    def __init__(self):
        self.left = 0
        self.right = 0
        self.N = 0
        self.Z = 1
        self.C = 0

    def set_flags(self, res):
        self.N = 1 if res < 0 else 0
        self.Z = 1 if res == 0 else 0

    def invert_string(self, s):
        return "".join(["1" if c == "0" else "0" for c in s])

    def to_unsigned(self, a):
        return int(self.invert_string(bin(abs(a))[2:].zfill(REAL_RANGE)), 2) + 1

    def to_signed(self, a):
        self.C = 1 if a >= REAL_MAX else 0
        a = a if self.C == 0 else a % REAL_MAX
        return a if MAX_NUM > a >= -MAX_NUM else -self.to_unsigned(a)

    def add(self, a, b):
        a = a if a >= 0 else self.to_unsigned(a)
        b = b if b >= 0 else self.to_unsigned(b)
        return self.to_signed(a + b)

    def sub(self, a, b):
        a = a if a >= 0 else self.to_unsigned(a)
        b = b if b >= 0 else self.to_unsigned(b)
        return self.add(a, self.to_unsigned(b))

    def div(self, a):
        self.C = a % 2
        return a // 2
    
    def mod(self, a, b):
        a = a if a >= 0 else self.to_unsigned(a)
        b = b if b >= 0 else self.to_unsigned(b)
        return self.to_signed(a % b)

    def calc_op(self, left, right, op_type):
        if op_type == "add":
            return self.add(left, right)
        elif op_type == "sub" or op_type == "cmp":
            return self.sub(left, right)
        elif op_type == "mod":
            return self.mod(left, right)
        raise Exception("Incorrect binary operation")

    def calc_nop(self, res, op_type):
        if op_type == "asl":
            return self.add(res, res)
        elif op_type == "asr":
            return self.div(res)
        elif op_type == "inc":
            return self.add(res, 1)
        elif op_type == "dec":
            return self.sub(res, 1)
        raise Exception("Incorrect unary operation")

    def calc(self, left, right, op_type, change_flags=False):
        is_left_char = True if isinstance(left, str) else False
        left = ord(left) if is_left_char else int(left)
        C = self.C

        if right is None:
            res = left
            is_right_char = False
            res = self.calc_nop(res, op_type)
        else:
            is_right_char = True if isinstance(right, str) else False
            right = ord(right) if is_right_char else int(right)
            res = self.calc_op(left, right, op_type)
        if change_flags:
            self.set_flags(res)
        else:
            self.C = C
        if is_left_char or is_right_char:
            res = chr(res)
            if is_left_char:
                left = chr(left)
        return left if op_type == "cmp" else res


class DataPath:
    registers = {"AC": 0, "AR": 0, "IP": 0, "PC": 0, "PS": 0, "DR": 0, "CR": 0}
    memory = []
    alu = ALU()

    def __init__(self):
        self.mem_size = MAX_ADDR + 1
        self.memory = [{"value": 0}] * self.mem_size
        self.registers["SP"] = STACK_P
        self.registers["AC"] = 0
        self.registers["PS"] = 2  # self.Z = 1
        self.output_buffer = []

    def get_reg(self, reg):
        return self.registers[reg]

    def set_reg(self, reg, val):
        self.registers[reg] = val

    def wr(self):
        self.memory[self.registers["AR"]] = {"value": self.registers["DR"]}
        if self.registers["AR"] == OUTPUT_MAP:
            self.output_buffer.append(self.registers["DR"])
            logger.info("OUTPUT " + str(self.output_buffer[-1]))

    def rd(self):
        self.registers["DR"] = self.memory[self.registers["AR"]]["value"]


class ControlUnit:
    def __init__(self, program, data_path, start_address, input_data, limit):
        self.program = program
        self.data_path = data_path
        self.limit = limit
        self.instr_counter = 0  # счетчик чтобы машина не работала бесконечно

        self.sig_latch_reg("IP", start_address)
        self._tick = 0
        self._map_instruction()

        self.input_data = input_data
        self.input_pointer = 0

    def _map_instruction(self):
        for i in self.program:
            self.data_path.memory[int(i["index"])] = i

    def get_reg(self, reg):
        return self.data_path.get_reg(reg)

    def sig_latch_reg(self, reg, val):
        self.data_path.set_reg(reg, val)

    def sig_write(self):
        self.data_path.wr()

    def sig_read(self):
        self.data_path.rd()

    def calc(self, left, right, op, change_flags=False):
        res = self.data_path.alu.calc(left, right, op, change_flags)
        if change_flags:
            self.sig_latch_reg("PS", self.get_reg("PS") ^ ((self.get_reg("PS") ^ self.data_path.alu.C) & 1))
            self.sig_latch_reg(
                "PS", self.get_reg("PS") ^ ((self.get_reg("PS") ^ (self.data_path.alu.Z << 1)) & (1 << 1))
            )
            self.sig_latch_reg(
                "PS", self.get_reg("PS") ^ ((self.get_reg("PS") ^ (self.data_path.alu.N << 2)) & (1 << 2))
            )
        return res

    def __tick(self):
        self._tick += 1

    def tick(self, comment=""):
        #self.__print__(comment)
        self._tick += 1
        if self.input_pointer < len(self.input_data) and self.input_data[self.input_pointer][0] == self.current_tick():
            data = self.input_data[self.input_pointer][1]
            self.sig_latch_reg("PS", self.get_reg("PS") | 8)  # 1 -> PS[4]
            logger.info("INPUT " + str(data))
            self.data_path.memory[INPUT_MAP] = {"value": data}  # data -> mem[IO], загрузили символ
            self.input_pointer += 1

    def current_tick(self):
        return self._tick

    def command_cycle(self, mode="main: "):
        while self.instr_counter < self.limit:
            go_next = self.decode_and_execute_instruction(mode)
            if (self.get_reg("PS") >> 3) & 1 == 1 and (self.get_reg("PS") >> 4) & 1 == 1:
                self.process_interrupt()
            if not go_next:
                return
            self.instr_counter += 1
            #Вывод состояние после инструкции
            self.__print__("")
            #logger.info("\n")
        if self.instr_counter >= self.limit:
            pass
            print("Limit exceeded!")

    def process_interrupt(self):
        #print("### Произошло прерывание на ткакте:", self.current_tick())
        mode = "int: "
        self.sig_latch_reg("PS", self.get_reg("PS") & ~(1 << 3))  # 0 -> PS[3]
        self.sig_latch_reg("DR", self.calc(0, self.get_reg("PS"), "add"))  # PS -> DR
        self.sig_latch_reg("AR", self.calc(0, self.get_reg("SP"), "add"))  # SP -> AR
        self.tick(mode + "0 -> PS[3], IP -> DR, SP -> AR")

        self.sig_write()  # DR -> mem[SP]
        self.tick(mode + "DR -> mem[SP]")

        self.sig_latch_reg("SP", self.calc(self.get_reg("SP"), 1, "sub"))
        self.sig_latch_reg("DR", self.calc(0, self.get_reg("IP"), "add"))  # IP -> DR
        self.sig_latch_reg("AR", self.calc(0, self.get_reg("SP"), "add"))  # SP -> AR
        self.tick(mode + "SP - 1 -> SP, 0 -> PS[4], IP -> DR, SP -> AR")

        self.sig_write()  # DR -> mem[SP]
        self.tick(mode + "DR -> mem[SP]")

        self.sig_latch_reg("SP", self.calc(self.get_reg("SP"), 1, "sub"))
        self.sig_latch_reg("AR", INT_VEC)  # адрес вектора прерываний
        self.sig_read()
        self.tick(mode + "SP - 1 -> SP, 0 -> AR, mem[AR] -> DR")

        self.sig_latch_reg("IP", self.calc(0, self.get_reg("DR"), "add"))
        self.tick(mode + "DR -> IP")

        self.command_cycle(mode)  # выполняем подпрограмму для прерывания

        self.sig_latch_reg("SP", self.calc(1, self.get_reg("SP"), "add"))
        self.sig_latch_reg("AR", self.calc(0, self.get_reg("SP"), "add"))
        self.sig_read()
        self.sig_latch_reg("IP", self.calc(0, self.get_reg("DR"), "add"))
        self.tick(mode + "SP + 1 -> SP, SP -> AR, mem[AR] -> DR, DR -> IP")

        self.sig_latch_reg("SP", self.calc(1, self.get_reg("SP"), "add"))
        self.sig_latch_reg("AR", self.calc(0, self.get_reg("SP"), "add"))
        self.sig_read()

        new_int = (self.get_reg("PS") >> 3) & 1
        self.sig_latch_reg("PS", self.calc(0, self.get_reg("DR"), "add") | new_int * 8)
        self.tick(mode + "SP + 1 -> SP, SP -> AR, mem[AR] -> DR, DR -> PS")

        if (self.get_reg("PS") >> 3) & 1 == 1 and (self.get_reg("PS") >> 4) & 1 == 1:
            self.process_interrupt()

    def decode_and_execute_instruction(self, mode=""):
        self.sig_latch_reg("AR", self.calc(0, self.get_reg("IP"), "add"))  # IP -> AR
        self.sig_latch_reg("IP", self.calc(1, self.get_reg("IP"), "add"))  # IP + 1 -> AR
        self.sig_latch_reg("CR", self.data_path.memory[self.get_reg("AR")])
        instr = self.get_reg("CR")
        opcode = instr["opcode"]

        self.tick(mode + "instr.f: IP -> AR, IP + 1 -> IP, mem[AR] -> DR, DR -> CR")

        if "opcode" not in instr.keys():
            return False

        cycle = "exec.f: "
        # адресная команда
        if "operand" in instr.keys():
            # в DR лежит адрес операнда или адрес адреса операнда
            self.sig_latch_reg("DR", int(self.get_reg("CR")["operand"]))  # CR -> alu -> DR (operand only)

            # цикл выборки адреса
            if instr["address"]:
                self.sig_latch_reg("AR", self.calc(0, self.get_reg("DR"), "add"))
                self.sig_read()
                self.tick(mode + "addr.f: CR[operand] -> DR, DR -> AR, mem[AR] -> DR")

            # цикл выборки операнда
            self.sig_latch_reg("AR", self.calc(0, self.get_reg("DR"), "add"))
            self.sig_read()
            self.tick(mode + "op.f: CR[operand] -> DR, DR -> AR, mem[AR] -> DR")

            if opcode == "load":
                self.sig_latch_reg("AC", self.calc(0, self.get_reg("DR"), "add", True))
                self.tick(mode + cycle + "DR -> AC")

            elif opcode == "store":
                self.sig_latch_reg("DR", self.calc(0, self.get_reg("AC"), "add"))
                self.sig_write()
                self.tick(mode + cycle + "AC -> DR, DR -> mem[AR]")

            elif opcode in branch_commands:
                ind = branch_commands.index(opcode)
                flag = branch_flags[ind]
                condition = True

                if (flag is not None) and flag[0] == "!":
                    condition = eval("not self.data_path.alu." + flag[1])
                elif flag is not None:
                    condition = eval("self.data_path.alu." + flag[0])
                if condition:
                    self.sig_latch_reg("IP", self.calc(0, self.get_reg("AR"), "add"))
                    self.tick(mode + cycle + "AR -> IP")
                else:
                    self.tick(mode + cycle + "NOP")
            else:
                # арифметическая операция
                self.sig_latch_reg("AC", self.calc(self.get_reg("AC"), self.get_reg("DR"), opcode, True))
                self.tick(mode + cycle + "AC " + opcode + " DR -> AC")
        # безадресная команда
        else:
            if opcode == "hlt":
                self.tick(mode + cycle + "end on simulation")
                return False
            elif opcode == "iret":
                self.tick(mode + cycle + " return from interrupt")
                return False
            elif opcode == "push":
                self.sig_latch_reg("DR", self.calc(self.get_reg("AC"), 0, "add"))  # AC -> DR
                self.sig_latch_reg("AR", self.calc(self.get_reg("SP"), 0, "add"))  # SP -> AR
                self.sig_latch_reg("SP", self.calc(self.get_reg("SP"), 1, "sub"))  # SP - 1 -> SP
                self.sig_write()
                self.tick(mode + cycle + "AC -> DR, SP -> AR, SP - 1 -> SP, DR -> mem[SP]")
            elif opcode == "pop":
                self.sig_latch_reg("SP", self.calc(self.get_reg("SP"), 1, "add"))  # SP + 1 -> SP
                self.sig_latch_reg("AR", self.calc(self.get_reg("SP"), 0, "add"))  # SP -> AR
                self.sig_read()
                self.sig_latch_reg("AC", self.calc(self.get_reg("DR"), 0, "add", True))  # DR -> AC
                self.tick(mode + cycle + "SP + 1 -> SP, SP -> AR, mem[SP] -> DR, DR -> AC")

            elif opcode == "di":
                self.sig_latch_reg("PS", self.get_reg("PS") & ~(1 << 4))
                self.tick(mode + cycle + "0 -> PS[4]")
            elif opcode == "ei":
                self.sig_latch_reg("PS", self.get_reg("PS") | 16)
                self.tick(mode + cycle + "1 -> PS[4]")
            elif opcode == "cla":
                self.sig_latch_reg("AC", self.calc(self.get_reg("AC"), self.get_reg("AC"), "sub", True))
                self.tick(mode + cycle + "0 -> AC")
            elif opcode == "nop":
                self.tick(mode + cycle + "NOP")
            else:
                # унарная арифметическая операция
                self.sig_latch_reg("AC", self.calc(self.get_reg("AC"), None, opcode, True))
                self.tick(mode + cycle + " " + opcode + " AC -> AC")
        #logger.info("\n")
        return True  # executed successfully

    def __print_symb__(self, text):
        return str((lambda x: ord(x) if isinstance(x, str) else x)(text))

    def __print__(self, comment):
        state_repr = (
            "TICK: {:4} | AC {:7} | IP: {:4} | AR: {:4} | PS: {:3} | DR: {:7} | SP : {:4} | mem[AR] {:7} | "
            "mem[SP] : {:3} | CR: {:12} |"
        ).format(
            self._tick,
            self.__print_symb__(self.get_reg("AC")),
            str(self.get_reg("IP")),
            str(self.get_reg("AR")),
            str(bin(self.get_reg("PS"))[2:].zfill(5)),
            self.__print_symb__(self.get_reg("DR")),
            str(self.get_reg("SP")),
            self.__print_symb__(self.data_path.memory[self.get_reg("AR")]["value"]),
            self.__print_symb__(self.data_path.memory[self.get_reg("SP")]["value"]),
            self.get_reg("CR")["opcode"]
            + (lambda x: " " + str(x["operand"]) if "operand" in x.keys() else "")(self.get_reg("CR")),
        )
        logger.info(state_repr)


def simulation(code, limit, input_data, start_addr):
    start_address = start_addr
    data_path = DataPath()
    control_unit = ControlUnit(code, data_path, start_address, input_data, limit)
    control_unit.command_cycle()
    return [control_unit.data_path.output_buffer, control_unit.instr_counter, control_unit.current_tick()]

def read_data_from_binary_file(filename):
    start_address = 0
    data = []
    with open(filename, "rb") as binary_file:
        start_address_bytes = binary_file.read(4)
        start_address = int(format(int.from_bytes(start_address_bytes, byteorder='big'), '032b'), 2)
        while True:
            address_bytes = binary_file.read(4)
            if not address_bytes:
                break
            instruction_bytes = binary_file.read(4)
            address = format(int.from_bytes(address_bytes, byteorder='big'), '032b')
            instruction = format(int.from_bytes(instruction_bytes, byteorder='big'), '032b')
            data.append((address, instruction))
    return start_address, data


def get_dicts_from_bin(filename):
    start_addres, datas = read_data_from_binary_file(filename)
    dicts = []
    for index, data in datas:
        temp =  {"index": int(index,2)}
        if(data[0] == '0'):
            if(data[1] == '0'):
                temp["value"] = int(data, 2)
            else:
                temp["value"] = chr(int(data[2:], 2))
            temp["opcode"] = "nop"
        else:
            temp["opcode"] = opcode_opname_mapping[data[3:8]]
            temp["value"] = 0
            if(data[1] == '1'):
                temp["operand"] = int(data[9:19],2)
                if(data[2] == '1'):
                    temp["address"] = True
                else:
                    temp["address"] = False
        dicts.append(temp)
    return start_addres, dicts

def main(code, input_f):
    with open(input_f, encoding="utf-8") as file:
        input_text = file.read()
        if not input_text:
            input_token = [(-1, -1)]
        else:
            input_token = eval(input_text)  # массив с парой символ-тик
    #start_addr, code = read_code(code)
    start_addr, code = get_dicts_from_bin(code)
    output, instr_num, ticks = simulation(
        code,
        limit=15000,
        input_data=input_token,
        start_addr=start_addr,
    )
    print(f"Output: {output}\nInstruction number: {instr_num}\nTicks: {ticks - 1}")


if __name__ == "__main__":
    assert len(sys.argv) == 3, "Wrong arguments: machine.py <code_file> <input_file>"
    _, code_file, input_file = sys.argv
    d = DataPath()
    main(code_file, input_file)
