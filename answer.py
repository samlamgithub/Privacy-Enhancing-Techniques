"""Coursework for 408H - Privacy Enhancing Techniques"""
# -*- coding: utf-8 -*-
#!/usr/bin/env python
import numpy as np
import math
import numpy.random as ran
import cryption
from Crypto.Cipher import AES



PADDING = '{'
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
unpad = lambda s: s.split(PADDING)[0]



def Encrypt(k1, k2, k, x):
    """
    An Encrypt function, encrypting (k, x)
    using the given keys k1 and k2 with AES.
    Padding must be added to keys and message
    because it's usually under 16 bytes required
    by AES.
    As x is 0 or 1, the message is the key k shifted
    by one bit, and this last bit (LSB) is replaced by x.
    """
    # print "xxx", k1, k2, k, x, "xxx"
    message = str(int(x) + (k << 1))
    message = pad(str(message))

    key1 = pad(str(k1))
    key2 = pad(str(k2))

    obj = AES.new(key1, AES.MODE_CBC, key2)

    return obj.encrypt(message)


def Decrypt2(k1, k2, ciphertext):
    """
    A Decrypt function, decrypting x and k
    using the given keys k1 and k2.
    """
    # print "xxx2 xx", k1, k2, ciphertext, "xxx"
    key1 = pad(str(k1))
    key2 = pad(str(k2))

    obj = AES.new(key1, AES.MODE_CBC, key2)

    message = obj.decrypt(ciphertext)
    message = unpad(str(message))
    message = int(message)

    k = message >> 1
    x = message & 1

    return k, x

AliceInputBits = np.arange(2)
BobInputBits = np.arange(2, 4)

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

def Encry(kX, kY, kZ, t):
    # message = str(int(t) + (kZ << 1))
    # cipher = AES.new(cryption.pad(str(kX)), AES.MODE_CBC, cryption.pad(str(kY)))
    # encoded = cryption.EncodeAES(cipher, message)
    # return encoded
    # print False
    #xxx 125 196 250 0 xxx
    return Encrypt(int(kX), int(kY), int(kZ), t)

def Decrypt(kX, kY, text):

    # cipher = AES.new(cryption.pad(str(kX)), AES.MODE_CBC,cryption.pad(str(kY)))
    # decoded = cryption.DecodeAES(cipher, text)
    # decoded = RemovePadding(decoded)
    # decoded = int(decoded)
    # k = decoded >> 1
    # x = decoded & 1
    # return k, x
    # # print "xxx", kX, kY, t, "xxx"
    # xxx2 xx 13 146 luanma xxx
    return Decrypt2(int(kX), int(kY), text)

def PrintBit(B):
    if bool(B):
        return "1"
    else:
        return "0"

def BinaryToDecimal(B):
    return 2 * int(B[0]) + int(B[1])

def CountWire(circuit):
    if isinstance(circuit, list):
        return 1 + CountWire(circuit[1]) + CountWire(circuit[2])
    else:
        return 1

def CircuitApplyOperation(circuit, index, operation):
    if not isinstance(circuit, list):
        return [operation(circuit, index)]

    total = CountWire(circuit)
    Returns = [[None, None]] * total
    firstWireCount = CountWire(circuit[1])
    Returns[1:(firstWireCount+1)] = CircuitApplyOperation(circuit[1], index + 1, operation)
    secondWireCount = CountWire(circuit[2])
    Returns[(firstWireCount+1):] = CircuitApplyOperation(circuit[2], index + firstWireCount +1, operation)
    return Returns

def ConstructTableForGate(gate, kKey, pKey):
    table = [['', ''], ['', '']]
    for i in np.arange(2):
        for j in np.arange(2):
            x = int(Xor(i, pKey[1]))
            y = int(Xor(j, pKey[2]))
            z = int(gate(x, y))
            t = int(Xor(z, pKey[0]))
            tmp2 = Encry(kKey[1][x], kKey[2][y], kKey[0][z], t)
            # print "tmp2: ", tmp2
            table[i][j] = tmp2
    # print table
    return table

def ConstructTablesForCircuit(circuit, kKey, pKey):
    if not isinstance(circuit, list):
        return [None]
    totoalWireCount = CountWire(circuit)
    FirstWireCount = CountWire(circuit[1])
    # print "FirstWireCount: ", FirstWireCount
    FirstGateCount = FirstWireCount / 2
    Tables = [None] * (totoalWireCount/2)
    Gate = circuit[0]
    Tables[1:(FirstGateCount+1)] = ConstructTablesForCircuit(circuit[1], kKey[1:(FirstWireCount+1), :], pKey[1:(FirstWireCount+1)])
    Tables[(FirstGateCount+1):] = ConstructTablesForCircuit(circuit[2], kKey[(FirstWireCount+1):, :], pKey[(FirstWireCount+1):])
    kKeyForCurrentGate = [kKey[0, :], kKey[1, :], kKey[FirstWireCount+1, :]]
    pKeyForCurrentGate = [pKey[0], pKey[1], pKey[FirstWireCount+1]]
    Tables[0] = ConstructTableForGate(Gate, kKeyForCurrentGate, pKeyForCurrentGate)
    # print "x ", x
    # print "table: ", Tables
    return Tables

def ConstructGarbledCircuit(circuit, InputBits):
    TotalWireCount = CountWire(circuit)
    kKeys = ran.random_integers(0, 256, [TotalWireCount, 2])
    pKeys = ran.random_integers(0, 1, [TotalWireCount])
    GarbleTables = ConstructTablesForCircuit(circuit, kKeys, pKeys)

    AliceEncyInput = CircuitApplyOperation(circuit, 0, lambda Input, Index: Xor(InputBits[int(Input)], int(pKeys[Index])) if int(Input) in AliceInputBits else None)
    AliceKKeys = CircuitApplyOperation(circuit, 0, lambda Input, Index: kKeys[Index, int(InputBits[int(Input)])] if int(Input) in AliceInputBits else None)

    BobPKeys = CircuitApplyOperation(circuit, 0, lambda Input, Index: pKeys[Index] if int(Input) in BobInputBits else None)
    BobPKeys[0] = pKeys[0]
    BobKKeys = CircuitApplyOperation(circuit, 0, lambda Input, Index: kKeys[Index, :] if int(Input) in BobInputBits else [0, 0])
    BobKKeys[0] = kKeys[0, :]
    BobKKeys = np.matrix(BobKKeys)

    return [circuit, GarbleTables, AliceEncyInput, AliceKKeys, BobPKeys, BobKKeys]

def GetCircuitForIndexInputWire(circuit, GarbleTables, AliceEncyInput, AliceKKeys, BobPKeys, BobKKeys, Index):
    Input1WireCount = CountWire(circuit[1])
    Input1GateCount = Input1WireCount / 2
    IndexWireCount = CountWire(circuit[Index])
    IndexGateCount = IndexWireCount / 2

    WIdxMin = (Index-1)*Input1WireCount + 1
    WIdxMax = WIdxMin + IndexWireCount
    GIdxMin = (Index-1)*Input1GateCount + 1
    GIdxMax = GIdxMin + IndexGateCount

    return  circuit[Index], GarbleTables[GIdxMin:GIdxMax],AliceEncyInput[WIdxMin:WIdxMax], AliceKKeys[WIdxMin:WIdxMax], BobPKeys[WIdxMin:WIdxMax],BobKKeys[WIdxMin:WIdxMax, :]

def EvaluateCircuit(circuit, GarbleTables, AliceEncyInput, AliceKKeys, BobPKeys, BobKKeys, Input):
    # print "input: ", Input
    # print "BobKKeys; ", BobKKeys
    if not isinstance(circuit, list):
        if circuit in AliceInputBits:
            kKey, EncryedValue = AliceKKeys[0], AliceEncyInput[0]
        else:
            BobInputBit = circuit - 2
            # print "BobInputBit: ", BobInputBit
            tmp = Input[BobInputBit]
            kKey = BobKKeys[0, tmp]
            EncryedValue = int(Xor(BobPKeys[0], Input[BobInputBit]))
        return kKey, EncryedValue

    circuit1, GarbleTables1, AliceEncyInput1, AliceKKeys1, BobPKeys1, BobKKeys1 = GetCircuitForIndexInputWire(circuit, GarbleTables, AliceEncyInput, AliceKKeys, BobPKeys, BobKKeys, 1)
    kKey1, EncryedValue1 = EvaluateCircuit(circuit1, GarbleTables1, AliceEncyInput1, AliceKKeys1, BobPKeys1, BobKKeys1, Input)
    circuit2, GarbleTables2, AliceEncyInput2, AliceKKeys2, BobPKeys2, BobKKeys2 = GetCircuitForIndexInputWire(circuit, GarbleTables, AliceEncyInput, AliceKKeys, BobPKeys, BobKKeys, 2)
    kKey2, EncryedValue2 = EvaluateCircuit(circuit2, GarbleTables2, AliceEncyInput2, AliceKKeys2, BobPKeys2, BobKKeys2, Input)
    GateTable = GarbleTables[0]
    EncryedOutput = GateTable[EncryedValue1][EncryedValue2]
    # print "xxx", kKey1, kKey2, EncryedOutput, "xxx"
    kZ, t = Decrypt(kKey1, kKey2, EncryedOutput)
    return kZ, t

def cmp(a, b):
    if a==b:
        return 0
    if a>b:
        return 1
    if a<b:
        return 3
    return 999

def main(circuit):
    # print "Truth-Table for function '%s':\n" % (FuncName)
    # print "   AB | CD || EF"
    # print "  ----|----||----"
    # p = pad("vjwoiowsivjwsadaa")
    # print p
    # x = unpad(p)
    # print x
    # return
    for A in [False, True]:
        for B in [False, True]:
            AliceInput = (A, B)
            AliceInputInt = BinaryToDecimal(AliceInput)
            circuitOut1, GarbleTables1, AliceEncyInput1, AliceKKeys1, BobPKeys1, BobKKeys1 = ConstructGarbledCircuit(circuit[0], AliceInput)
            circuitOut2, GarbleTables2, AliceEncyInput2, AliceKKeys2, BobPKeys2, BobKKeys2 = ConstructGarbledCircuit(circuit[1], AliceInput)
            # print "BobKKeys1: " , BobKKeys1
            # print "BobKKeys2: " , BobKKeys2
            Out1DecryKey = BobPKeys1[0]
            Out2DecryKey = BobPKeys2[0]

            for C in [False, True]:
                for D in [False, True]:
                    # Evaluate each garbled circuit with the second input
                    _, EncryedOut1 = EvaluateCircuit(circuitOut1, GarbleTables1, AliceEncyInput1, AliceKKeys1, BobPKeys1, BobKKeys1, (C, D))
                    _, EncryedOut2 = EvaluateCircuit(circuitOut2, GarbleTables2, AliceEncyInput2, AliceKKeys2, BobPKeys2, BobKKeys2, (C, D))
                    Out1 = Xor(EncryedOut1, Out1DecryKey)
                    Out2 = Xor(EncryedOut2, Out2DecryKey)

                    BobInputInt = BinaryToDecimal((C, D))
                    OutInt = BinaryToDecimal((Out1, Out2))
                    # print OutInt
                    # Print the result line
                    print "   %d%d | %d%d || %d%d    (%d, %d) = %d !!! %d" % \
                        (int(A), int(B), int(C), int(D), int(Out1), int(Out2), #FuncName,
                         AliceInputInt, BobInputInt, OutInt, cmp(AliceInputInt, BobInputInt))


                    #
                    # if FuncValid(AliceInputInt, BobInputInt) != OutInt:
                    #     print "There's something wrong..."
                    #     sys.exit(1)
    # Print a new-line at the end
    # print ''
    # print len(circuit)
    # O1 = circuit[0]
    # print Compute2(O1)
    # print 0, 1, 2, 3, ":  ", "O1", "O2"
    # for A in [False, True]:
    #         for B in [False, True]:
    #                 for C in [False, True]:
    #                         for D in [False, True]:
    #                             print Compute2(O1, A, B, C, D)
                                # O1, O2 = Compute(A, B, C, D)
                                # print PrintBit(A), PrintBit(B), PrintBit(C), PrintBit(D), ":  ", PrintBit(O1), " ", PrintBit(O2)

    return 0

if __name__ == "__main__":
    O1 = [Or, [Or, [And, [Nor, 0, 1], 3], [And, [Nand, 0, 0], 2]], [And, [And, 2, [Nand, 1, 1]], 3]]
    O2 = [Or, [Xor, 0, 2], [Xor, 1, 3]]
    circuit = [O1, O2]
    main(circuit)
