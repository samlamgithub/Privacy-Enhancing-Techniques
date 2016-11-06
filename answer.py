"""Coursework for 408H - Privacy Enhancing Techniques"""
# -*- coding: utf-8 -*-
import numpy as np
import math

def And(a, b):
    return bool(a) and bool(b)

def Or(a, b):
    return bool(a) or bool(b)

def Or3(a, b, c):
    return Or(Or(a, b), c)

def Not(a):
    return not bool(a)

def Nand(a, b):
    return not And(a, b)

def Nor(a, b):
    return not Or(a, b)

def Xor(a, b):
    return bool(a) != bool(b)

def Encry(Pub, M):
    return M

def Decry(Pri, M):
    return M

def PrintBit(B):
    if bool(B):
        return "1"
    else:
        return "0"

def Compute(A, B, C, D):
    O1111 = Not(A)
    O1112 = Not(B)
    O112 = D
    O111 = And(O1111, O1112)
    O11 = And(O111, O112)
    O121 = Not(A)
    O122 = C
    O12 = And(O121, O122)
    O1311 = C
    O1312 = Not(B)
    O131 = And(O1311, O1312)
    O132 = D
    O13 = And(O131, O132)
    O211 = A
    O212 = C
    O21 = Xor(O211, O212)
    O221 = B
    O222 = D
    O22 = Xor(O221, O222)
    O1 = Or3(O11, O12, O13)
    O2 = Or(O21, O22)
    return O1, O2

def main():
    print "A", "B", "C", "D", ":  ", "O1", "O2"
    for A in [False, True]:
            for B in [False, True]:
                    for C in [False, True]:
                            for D in [False, True]:
                                O1, O2 = Compute(A, B, C, D)
                                print PrintBit(A), PrintBit(B), PrintBit(C), PrintBit(D), ":  ", PrintBit(O1), " ", PrintBit(O2)

    return 0

if __name__ == "__main__":
    main()
