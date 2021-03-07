from sys import platform
from ctypes import (CDLL,
                    c_char,
                    c_uint8,
                    c_uint16,
                    c_uint32,
                    c_int8,
                    c_bool,
                    c_size_t,
                    POINTER,
                    cast,
                    create_string_buffer,
                    byref)

ALGORITHM_AES               = 0
ALGORITHM_SHA256            = 1
ALGORITHM_HMACSHA256        = 2
ALGORITHM_AES_HMACSHA256    = 3

OP_ENCRYPT = 1 << 8
OP_DECRYPT = 2 << 8

MODE_ECB = 1
MODE_CBC = 2
MODE_OFB = 3
MODE_CTR = 4
MODE_CFB = 5

UPDATE_FLAG_FINIT = 1 << 15
UPDATE_FLAG_RESET = 1 << 14
UPDATE_FLAG_SET_IV = UPDATE_FLAG_RESET
UPDATE_FLAG_SETNONCE = 1 << 13
UPDATE_FLAG_AUTH = 1 << 12

def load_L0():
    if platform == "linux":
        return CDLL("/home/axel/Workspace/SEcube/lib/L0.so")
    else:
        return CDLL("C:\\Users\\axelc\\Workspace\\MSc-SEcubeWrapper\\lib\\L0.dll",
                           winmode=0x00000008)


def load_L1():
    if platform == "linux":
        return CDLL("/home/axel/Workspace/SEcube/lib/L1.so")
    else:
        return CDLL("C:\\Users\\axelc\\Workspace\\MSc-SEcubeWrapper\\lib\\L1.dll",
                           winmode=0x00000008)


# Setup L0 library
L0_lib = load_L0()

L0Handle = POINTER(c_char)

L0_lib.L0_create.restype = L0Handle
L0_lib.L0_destroy.argtypes = [L0Handle]

L0_lib.L0_getNumberDevices.restype = c_uint8
L0_lib.L0_getNumberDevices.argtypes = [L0Handle]

# Setup L1 library
L1_lib = load_L1()

L1Handle = POINTER(c_char)

L1_lib.L1_create.restype = L1Handle
L1_lib.L1_destroy.argtypes = [L1Handle]

L1_lib.L1_Login.argtypes = [L1Handle, POINTER(c_uint8),
                            c_uint16, c_bool]
L1_lib.L1_Login.restype = c_int8

L1_lib.L1_Logout.argtypes = [L1Handle]
L1_lib.L1_Logout.restype = c_int8

L1_lib.L1_CryptoSetTimeNow.argtypes = [L1Handle]
L1_lib.L1_Logout.restype = c_int8

L1_lib.L1_CryptoSetTimeNow.argtypes = [L1Handle]
L1_lib.L1_CryptoSetTimeNow.restype = c_int8

L1_lib.L1_CryptoInit.argtypes = [L1Handle, c_uint16, c_uint16, c_uint32,
                                 POINTER(c_uint32)]
L1_lib.L1_CryptoInit.restype = c_int8

L1_lib.L1_CryptoUpdate.argtypes = [L1Handle, c_uint32, c_uint16, c_uint16,
                                   POINTER(c_uint8), POINTER(c_uint16),
                                   POINTER(c_uint8)]
L1_lib.L1_CryptoUpdate.restype = c_int8

# Demo
pin = (c_uint8 * 32) (
    116,101,115,116, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
)

print("SEcube L0 loaded: ", L0_lib)
print("SEcube L1 loaded: ", L1_lib)

l0 = L0_lib.L0_create()

num_devices = L0_lib.L0_getNumberDevices(l0)
print("Number of devices connected: ", num_devices)

l1 = L1_lib.L1_create()

res = L1_lib.L1_Login(l1, pin, 100, True)
if res < 0:
    L1_lib.L1_destroy(l1)
    L0_lib.L0_destroy(l0)
    exit(1)
print("Login successful!")

L1_lib.L1_CryptoSetTimeNow(l1)
print("L1 CryptoSetTime")

dataIn = create_string_buffer(b"AAAAA", 8)
dataInLen = c_uint16(16)

dataOut = create_string_buffer(16)
dataOutLen = c_uint16(0)

# Encrypt
sessionID = c_uint32()
if L1_lib.L1_CryptoInit(l1, ALGORITHM_AES, OP_ENCRYPT | MODE_ECB, 2000,
                     byref(sessionID)) < 0:
    L1_lib.L1_Logout(l1)
    print("Logged out!")
    L1_lib.L1_destroy(l1)
    L0_lib.L0_destroy(l0)
if L1_lib.L1_CryptoUpdate(l1, sessionID,
                          OP_ENCRYPT | MODE_ECB | UPDATE_FLAG_FINIT,
                          dataInLen, cast(dataIn, POINTER(c_uint8)),
                          byref(dataOutLen), cast(dataOut, POINTER(c_uint8))) < 0:
    L1_lib.L1_Logout(l1)
    print("Logged out!")
    L1_lib.L1_destroy(l1)
    L0_lib.L0_destroy(l0)

dataIn = create_string_buffer(16)
dataInLen = c_uint16(16)

#Decrypt
if L1_lib.L1_CryptoInit(l1, ALGORITHM_AES, OP_DECRYPT | MODE_ECB, 2000,
                     byref(sessionID)) < 0:
    L1_lib.L1_Logout(l1)
    print("Logged out!")
    L1_lib.L1_destroy(l1)
    L0_lib.L0_destroy(l0)
if L1_lib.L1_CryptoUpdate(l1, sessionID,
                          OP_DECRYPT | MODE_ECB | UPDATE_FLAG_FINIT,
                          dataOutLen, cast(dataOut, POINTER(c_uint8)),
                          byref(dataInLen), cast(dataIn, POINTER(c_uint8))) < 0:
    L1_lib.L1_Logout(l1)
    print("Logged out!")
    L1_lib.L1_destroy(l1)
    L0_lib.L0_destroy(l0)

print(dataOut.raw)
print(dataIn.raw)

L1_lib.L1_Logout(l1)
print("Logged out!")

L1_lib.L1_destroy(l1)
L0_lib.L0_destroy(l0)
print("L0 and L1 destroyed")
