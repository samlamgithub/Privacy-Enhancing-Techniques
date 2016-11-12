# -*- coding: utf-8 -*-
#!/usr/bin/env python
"""Coursework for 408H - Privacy Enhancing Techniques"""
import numpy as np
import numpy.random as ran
from Crypto import Random
from Crypto.Cipher import AES
import base64

PADDING = '{'
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
unpad = lambda s: s.split(PADDING)[0]
AliceInputBits = np.arange(2)
BobInputBits = np.arange(2, 4)
BS = 16

def And(a, b):
    return bool(a) and bool(b)

def Or(a, b):
    return bool(a) or bool(b)

def Nand(a, b):
    return not And(a, b)

def Nor(a, b):
    return not Or(a, b)

def Xor(a, b):
    return bool(a) != bool(b)

def encrypt(key, raw):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.urlsafe_b64encode(iv + cipher.encrypt(raw))

def decrypt(key, enc):
    enc = base64.urlsafe_b64decode(enc.encode('utf-8'))
    iv = enc[:BS]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[BS:]))

def Encry(kX, kY, kZ, t):
    message = pad(str(int(t) + (kZ << 1)))
    key = pad(str(kX+kY))
    return encrypt(key, message)

def Decrypt(kX, kY, text):
    key = pad(str(kX+kY))
    message = int(decrypt(key, text))
    t, kZ = message >> 1, message & 1
    return t, kZ

def PrintBit(B):
    if bool(B):
        return "1 "
    else:
        return "0 "

def BinaryToDecimal(B):
    return 2 * int(B[0]) + int(B[1])

def PrintDecimal(D):
    return str(D/2) + str(D%2)

def CountWire(circuit):
    if isinstance(circuit, list):
        return 1 + CountWire(circuit[1]) + CountWire(circuit[2])
    else:
        return 1

def CircuitApplyOperation(circuit, index, operation):
    if not isinstance(circuit, list):
        return [operation(circuit, index)]
    total = CountWire(circuit)
    Returns = total * [np.array([None, None])]
    firstWireCount = CountWire(circuit[1])
    Returns[1:(firstWireCount+1)] = CircuitApplyOperation(circuit[1], index + 1, operation)
    Returns[(firstWireCount+1):] = CircuitApplyOperation(circuit[2], index + firstWireCount + 1, operation)
    return Returns

def ConstructTableForGate(gate, kKey, pKey):
    table = []
    for i in np.arange(2):
        js = []
        for j in np.arange(2):
            x = int(Xor(i, pKey[1]))
            y = int(Xor(j, pKey[2]))
            z = int(gate(x, y))
            t = int(Xor(z, pKey[0]))
            cipher = Encry(kKey[1][x], kKey[2][y], kKey[0][z], t)
            js.append(cipher)
        table.append(js)
    return table

def ConstructTablesForCircuit(circuit, kKey, pKey):
    if not isinstance(circuit, list):
        return [None]
    totoalWireCount = CountWire(circuit)
    FirstWireCount = CountWire(circuit[1])
    FirstGateCount = FirstWireCount / 2
    GarbedTables = (totoalWireCount/2) * [None]
    Gate = circuit[0]
    GarbedTables[1:(FirstGateCount+1)] = ConstructTablesForCircuit(circuit[1], kKey[1:(FirstWireCount+1), :], pKey[1:(FirstWireCount+1)])
    GarbedTables[(FirstGateCount+1):] = ConstructTablesForCircuit(circuit[2], kKey[(FirstWireCount+1):, :], pKey[(FirstWireCount+1):])
    kKeyForCurrentGate = [kKey[0, :], kKey[1, :], kKey[FirstWireCount+1, :]]
    pKeyForCurrentGate = [pKey[0], pKey[1], pKey[FirstWireCount+1]]
    GarbedTables[0] = ConstructTableForGate(Gate, kKeyForCurrentGate, pKeyForCurrentGate)
    return GarbedTables

def ConstructGarbledCircuit(circuit, InputBits):
    TotalWireCount = CountWire(circuit)
    kKeys = ran.random_integers(0, 1024, [TotalWireCount, 2])
    pKeys = ran.random_integers(0, 1, [TotalWireCount])
    GarbleTables = ConstructTablesForCircuit(circuit, kKeys, pKeys)
    AliceEncyInput = CircuitApplyOperation(circuit, 0, lambda Input, Index: Xor(InputBits[int(Input)], int(pKeys[Index])) if int(Input) in AliceInputBits else None)
    AliceKKeys = CircuitApplyOperation(circuit, 0, lambda Input, Index: kKeys[Index, int(InputBits[int(Input)])] if int(Input) in AliceInputBits else None)
    BobPKeys = CircuitApplyOperation(circuit, 0, lambda Input, Index: pKeys[Index] if int(Input) in BobInputBits else None)
    BobPKeys[0] = pKeys[0]
    BobKKeys = CircuitApplyOperation(circuit, 0, lambda Input, Index: kKeys[Index, :] if int(Input) in BobInputBits else np.array([0, 0]))
    BobKKeys[0] = kKeys[0, :]
    BobKKeys = np.matrix(BobKKeys).reshape([len(BobKKeys), 2])
    return circuit, GarbleTables, AliceEncyInput, AliceKKeys, BobPKeys, BobKKeys

def GetCircuitForIndexInputWire(circuit, GarbleTables, AliceEncyInput, AliceKKeys, BobPKeys, BobKKeys, Index):
    FirstWireCount = CountWire(circuit[1])
    FirstWireGateCount = FirstWireCount / 2

    if Index == 1:
        return circuit[1], GarbleTables[1:1+FirstWireGateCount],AliceEncyInput[1:1+FirstWireCount], AliceKKeys[1:1+FirstWireCount], BobPKeys[1:1+FirstWireCount],BobKKeys[1:1+FirstWireCount, :]
    elif Index == 2:
        SecondWireCount = CountWire(circuit[2])
        SecondWireGateCount = SecondWireCount / 2
        SecondWireStartIndex = FirstWireCount + 1
        SecondWireEndIndex = SecondWireStartIndex + SecondWireCount
        SecondWireGateStartIndex = FirstWireGateCount + 1
        SecondWireGateEndIndex = SecondWireGateStartIndex + SecondWireGateCount

        return circuit[2], GarbleTables[SecondWireGateStartIndex:SecondWireGateEndIndex],AliceEncyInput[SecondWireStartIndex:SecondWireEndIndex], AliceKKeys[SecondWireStartIndex:SecondWireEndIndex], BobPKeys[SecondWireStartIndex:SecondWireEndIndex], BobKKeys[SecondWireStartIndex:SecondWireEndIndex, :]

def EvaluateCircuit(circuit, GarbleTables, AliceEncyInput, AliceKKeys, BobPKeys, BobKKeys, Input):
    if not isinstance(circuit, list):
        if circuit in AliceInputBits:
            kKey, EncryedValue = AliceKKeys[0], AliceEncyInput[0]
        else:
            BobInputBit = int(circuit - 2)
            kKey = BobKKeys[0, Input[BobInputBit]]
            EncryedValue = int(Xor(BobPKeys[0], Input[BobInputBit]))
        return kKey, EncryedValue

    circuit1, GarbleTables1, AliceEncyInput1, AliceKKeys1, BobPKeys1, BobKKeys1 = GetCircuitForIndexInputWire(circuit, GarbleTables, AliceEncyInput, AliceKKeys, BobPKeys, BobKKeys, 1)
    kKey1, EncryedValue1 = EvaluateCircuit(circuit1, GarbleTables1, AliceEncyInput1, AliceKKeys1, BobPKeys1, BobKKeys1, Input)
    circuit2, GarbleTables2, AliceEncyInput2, AliceKKeys2, BobPKeys2, BobKKeys2 = GetCircuitForIndexInputWire(circuit, GarbleTables, AliceEncyInput, AliceKKeys, BobPKeys, BobKKeys, 2)
    kKey2, EncryedValue2 = EvaluateCircuit(circuit2, GarbleTables2, AliceEncyInput2, AliceKKeys2, BobPKeys2, BobKKeys2, Input)
    GateTable = GarbleTables[0]
    EncryedOutput = GateTable[int(EncryedValue1)][int(EncryedValue2)]
    kZ, t = Decrypt(kKey1, kKey2, EncryedOutput)
    return kZ, t

def cmp(a, b, c, d):
    Alice = BinaryToDecimal([a, b])
    Bob = BinaryToDecimal([c, d])
    if Alice == Bob:
        return 0
    if Alice > Bob:
        return 1
    if Alice < Bob:
        return 3

def main(circuit):
    print "A ", "B ", "C ", "D ", ":  ", "O1  ", "O2  ", "CMP"
    for A in [False, True]:
        for B in [False, True]:
            AliceInput = (A, B)
            circuitOut1, GarbleTables1, AliceEncyInput1, AliceKKeys1, BobPKeys1, BobKKeys1 = ConstructGarbledCircuit(circuit[0], AliceInput)
            circuitOut2, GarbleTables2, AliceEncyInput2, AliceKKeys2, BobPKeys2, BobKKeys2 = ConstructGarbledCircuit(circuit[1], AliceInput)
            Out1DecryKey = BobPKeys1[0]
            Out2DecryKey = BobPKeys2[0]
            for C in [False, True]:
                for D in [False, True]:
                    _, EncryedOut1 = EvaluateCircuit(circuitOut1, GarbleTables1, AliceEncyInput1, AliceKKeys1, BobPKeys1, BobKKeys1, (C, D))
                    _, EncryedOut2 = EvaluateCircuit(circuitOut2, GarbleTables2, AliceEncyInput2, AliceKKeys2, BobPKeys2, BobKKeys2, (C, D))
                    Out1 = Xor(EncryedOut1, Out1DecryKey)
                    Out2 = Xor(EncryedOut2, Out2DecryKey)
                    print PrintBit(A), PrintBit(B), PrintBit(C), PrintBit(D), ":  ", PrintBit(Out1), " ", PrintBit(Out2), " ", PrintDecimal(cmp(A, B, C, D))
    return 0

if __name__ == "__main__":
    O1 = [Or, [Or, [And, [Nor, 0, 1], 3], [And, [Nand, 0, 0], 2]], [And, [And, 2, [Nand, 1, 1]], 3]]
    O2 = [Or, [Xor, 0, 2], [Xor, 1, 3]]
    circuit = [O1, O2]
    main(circuit)
