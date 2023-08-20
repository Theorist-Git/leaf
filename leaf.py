#!/usr/bin/python3

from enum import Enum, auto
import sys
import subprocess


class StkOperations(Enum):
    # Starts from 1 i.e PUSH = 1
    PUSH = auto()
    PLUS = auto()
    MINUS = auto()
    DUMP = auto()
    OP_COUNT = auto()


def push(x):
    command: tuple = (StkOperations.PUSH.name, x)

    return command


def plus():
    command: tuple = (StkOperations.PLUS.name,)

    return command


def minus():
    command: tuple = (StkOperations.MINUS.name,)

    return command


def dump():
    command: tuple = (StkOperations.DUMP.name,)

    return command


def simulate(program):
    stk = []
    for op in program:
        assert StkOperations.OP_COUNT.value == 5, "Some operation is unhandled"
        if op[0] == StkOperations.PUSH.name:
            stk.append(op[1])

        elif op[0] == StkOperations.PLUS.name:
            op_1 = stk.pop()
            op_2 = stk.pop()

            add = op_2 + op_1
            stk.append(add)

        elif op[0] == StkOperations.MINUS.name:
            op_1 = stk.pop()
            op_2 = stk.pop()

            add = op_2 - op_1
            stk.append(add)

        elif op[0] == StkOperations.DUMP.name:
            out = stk.pop()
            print(out)

        else:
            raise TypeError("Invalid Operation Type")


def compile(program):
    with open(f"{sys.argv[0].split('.')[1][1:]}.asm", "w") as f:
        f.write(
            """; AUTOGEN by LEAF.PY
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
        for op in program:
            assert StkOperations.OP_COUNT.value == 5, "Some operation is unhandled"
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

            elif op[0] == StkOperations.DUMP.name:
                f.write(f"    pop rdi\n")
                f.write(f"    call dump\n")

            else:
                raise NotImplementedError(f"Invalid Operation in program: {op}")

        f.write("""
    mov rax, 60
    mov rdi, 0
    syscall
        """)

    subprocess.call(["./build.sh"])


def usage():
    print("USAGE: leaf.py <COMMAND> [ARGS]")
    print("COMMANDS:\n\tsim : simulate the program stack.\n\tcom : compile the program")
    print("ERROR: No command specified")


prog = [
    push(34),
    push(35),
    plus(),
    dump(),
    push(500),
    push(80),
    minus(),

    dump(),
]

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
        exit(1)

    cmd = sys.argv[1]

    if cmd == "sim":
        simulate(prog)
    elif cmd == "com":
        compile(prog)
    else:
        print("UNKNOWN COMMAND")
        usage()
        exit(1)
