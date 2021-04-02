g++ -O0 -c -o obj\initialise.o helpers\initialise.cpp
g++ -O0 -c -o obj\keys_and_algorithms.o helpers\keys_and_algorithms.cpp

g++ -o bin\initialise.exe ^
    obj\L0.o ^
    obj\L0_commodities.o ^
    obj\L0_communication.o ^
    obj\L0_provision.o ^
    obj\L0_base.o ^
    obj\sha256.o ^
    obj\aes256.o ^
    obj\pbkdf2.o ^
    obj\L1_base.o ^
    obj\L1_login_logout.o ^
    obj\L1_security.o ^
    obj\L1.o ^
    obj\initialise.o

g++ -o bin\keys_and_algorithms.exe ^
    obj\L0.o ^
    obj\L0_commodities.o ^
    obj\L0_communication.o ^
    obj\L0_provision.o ^
    obj\L0_base.o ^
    obj\sha256.o ^
    obj\aes256.o ^
    obj\pbkdf2.o ^
    obj\L1_base.o ^
    obj\L1_login_logout.o ^
    obj\L1_security.o ^
    obj\L1.o ^
    obj\keys_and_algorithms.o
