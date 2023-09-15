#!/usr/bin/python3

from enum import Enum, auto
import sys
import subprocess


class StkOperations(Enum):
    # Starts from 1 i.e PUSH = 1
    PUSH = auto()
    PLUS = auto()
    MINUS = auto()
    EQUALITY = auto()
    IF = auto()
    ELSE = auto()
    DUPLICATE = auto()
    GREATER_THAN = auto()
    END = auto()
    DUMP = auto()
    OP_COUNT = auto()


def push(x):
    command: tuple = (StkOperations.PUSH.name, x)

    return command


def plus():
    command: tuple = (StkOperations.PLUS.name, )

    return command


def minus():
    command: tuple = (StkOperations.MINUS.name, )

    return command


def greater_than():
    command: tuple = (StkOperations.GREATER_THAN.name, )

    return command


def equality():
    command: tuple = (StkOperations.EQUALITY.name, )

    return command


def if_condition():
    command: tuple = (StkOperations.IF.name, )

    return command


def else_condition():
    command: tuple = (StkOperations.ELSE.name, )

    return command


def duplicate():
    command: tuple = (StkOperations.DUPLICATE.name, )

    return command


def end():
    command: tuple = (StkOperations.END.name, )

    return command


def dump():
    command: tuple = (StkOperations.DUMP.name, )

    return command


def ret_op(op):
    if op == "+":
        return plus()
    elif op == "-":
        return minus()
    elif op == "DUMP" or op == "dump":
        return dump()
    elif op == ">":
        return greater_than()
    elif op == "==":
        return equality()
    elif op == "if":
        return if_condition()
    elif op == "else":
        return else_condition()
    elif op == "dup":
        return duplicate()
    elif op == "end":
        return end()
    elif op.lstrip("-").isdigit():
        return push(int(op))
    else:
        return None, op


def add_reference(program):
    stk = []
    for i in range(len(program)):
        op = program[i]

        if op[0] == StkOperations.IF.name:
            stk.append(i)

        elif op[0] == StkOperations.ELSE.name:
            if_pos = stk.pop()
            assert program[if_pos][0] == StkOperations.IF.name

            # `if` block stores relative position of instruction set to be executed
            # if the `if` condition is false.
            program[if_pos] = (StkOperations.IF.name, i + 1)
            stk.append(i)

        elif op[0] == StkOperations.END.name:
            block_pos = stk.pop()
            program[block_pos] = (program[block_pos][0], i)

    return program


def load_program(file_path):
    from pathlib import Path
    file_path = Path(file_path)

    if not file_path.name.endswith(".lf"):
        raise ValueError("Expected a .lf file")
    with open(file_path, "r") as f:
        return add_reference([ret_op(op) for op in f.read().split()])


def compile(program):
    from pathlib import Path
    f_name = Path(sys.argv[2]).stem

    with open(f"{f_name}.asm", "w") as f:
        f.write(
            f"""; AUTOGEN by LEAF.PY for {sys.argv[2]}
section .text
    dump:
        push    rbp
        mov     rbp, rsp
        sub     rsp, 64
        mov     QWORD [rbp-56], rdi
        mov     QWORD [rbp-8], 0
        mov     eax, 31
        sub     rax, QWORD [rbp-8]
        mov     BYTE [rbp-48+rax], 10
        add     QWORD [rbp-8], 1
    .L2:
        mov     rcx, QWORD [rbp-56]
        mov  rdx, -3689348814741910323
        mov     rax, rcx
        mul     rdx
        shr     rdx, 3
        mov     rax, rdx
        sal     rax, 2
        add     rax, rdx
        add     rax, rax
        sub     rcx, rax
        mov     rdx, rcx
        mov     eax, edx
        lea     edx, [rax+48]
        mov     eax, 31
        sub     rax, QWORD [rbp-8]
        mov     BYTE [rbp-48+rax], dl
        add     QWORD [rbp-8], 1
        mov     rax, QWORD [rbp-56]
        mov  rdx, -3689348814741910323
        mul     rdx
        mov     rax, rdx
        shr     rax, 3
        mov     QWORD [rbp-56], rax
        cmp     QWORD [rbp-56], 0
        jne     .L2
        mov     eax, 32
        sub     rax, QWORD [rbp-8]
        lea     rdx, [rbp-48]
        lea     rcx, [rdx+rax]
        mov     rax, QWORD [rbp-8]
        mov     rdx, rax
        mov     rsi, rcx
        mov     edi, 1
        mov     rax, 1
        syscall
        nop
        leave
        ret
        
    global _start

_start:
"""
        )
        for i in range(len(program)):
            op = program[i]

            if op[0] == StkOperations.PUSH.name:
                f.write(f"    push {op[1]}\n")

            elif op[0] == StkOperations.PLUS.name:
                f.write(f"    pop rax\n")
                f.write(f"    pop rbx\n")

                f.write(f"    add rbx, rax\n")
                f.write(f"    push rbx\n")

            elif op[0] == StkOperations.MINUS.name:
                f.write(f"    pop rax\n")
                f.write(f"    pop rbx\n")

                f.write(f"    sub rbx, rax\n")
                f.write(f"    push rbx\n")

            elif op[0] == StkOperations.EQUALITY.name:
                f.write(f"    mov rcx, 0\n")
                f.write(f"    mov rdx, 1\n")

                f.write(f"    pop rax\n")
                f.write(f"    pop rbx\n")

                f.write(f"    cmp rax, rbx\n")
                f.write(f"    cmove rcx, rdx\n")
                f.write(f"    push rcx\n")

            elif op[0] == StkOperations.IF.name:
                assert len(op) == 2, f"if Operation {op} doesn't provide reference to end block"

                f.write(f"    pop rax\n")
                # test sets zero flag if bitwise and of the numbers in rax is 0
                # for equal operands, say `a` and `b`, a&b = 0
                f.write(f"    test rax, rax\n")

                f.write(f"    jz addr_{op[1]}\n")
                f.write(f"    ; Will be executed for a true `if` statement\n")

            elif op[0] == StkOperations.ELSE.name:
                assert len(op) == 2, f"`else` Operation {op} doesn't provide reference to end block"

                f.write(f"    jmp addr_{op[1]}\n")
                f.write(f"addr_{i + 1}:\n")

            elif op[0] == StkOperations.DUPLICATE.name:

                f.write(f"    pop rax\n")
                f.write(f"    push rax\n")
                f.write(f"    push rax\n")

            elif op[0] == StkOperations.GREATER_THAN.name:

                f.write(f"    mov rcx, 0\n")
                f.write(f"    mov rdx, 1\n")

                f.write(f"    pop rax\n")
                f.write(f"    pop rbx\n")

                f.write(f"    cmp rbx, rax\n")
                f.write(f"    cmovg rcx, rdx\n")
                f.write(f"    push rcx\n")

            elif op[0] == StkOperations.END.name:
                f.write(f"addr_{i}:\n")

            elif op[0] == StkOperations.DUMP.name:
                f.write(f"    pop rdi\n")
                f.write(f"    call dump\n")

            else:
                raise NotImplementedError(f"Invalid Operation in program: {op}")

        f.write("""\tmov rax, 60
    mov rdi, 0
    syscall
        """)

    subprocess.call(["./build.sh", f"{f_name}"])


def usage():
    print("USAGE: leaf.py <COMMAND> [ARGS]")
    print("COMMANDS:\n\t<sim> [file] : simulate the program stack.\n\t<com> [file] : compile the program")
    print("ERROR: No command specified")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
        exit(1)

    cmd = sys.argv[1]
    file = sys.argv[2]

    prog = load_program(file_path=file)
    print(prog)

    if cmd == "com":
        compile(prog)
    else:
        print("UNKNOWN COMMAND")
        usage()
        exit(1)
