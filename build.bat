g++ -O0 -g3 -fPIC -Wall -c -o obj\L0_base.o SEcubeSources\L0\L0Base\L0_base.cpp
g++ -O0 -g3 -fPIC -Wall -c -o obj\L0_commodities.o SEcubeSources\L0\L0_commodities.cpp
g++ -O0 -g3 -fPIC -Wall -c -o obj\L0_communication.o SEcubeSources\L0\L0_communication.cpp
g++ -O0 -g3 -fPIC -Wall -c -o obj\L0_provision.o SEcubeSources\L0\L0_provision.cpp
g++ -O0 -g3 -fPIC -Wall -c -o obj\L0.o SEcubeSources\L0\L0.cpp

g++ -O3 -g3 -fPIC -Wall -c -o obj\aes256.o SEcubeSources\L1\CryptoLibraries\aes256.cpp
gcc -O3 -g3 -fPIC -Wall -c -o obj\sha256.o SEcubeSources\L1\CryptoLibraries\sha256.c
gcc -O3 -g3 -fPIC -Wall -c -o obj\pbkdf2.o SEcubeSources\L1\CryptoLibraries\pbkdf2.c

g++ -O3 -g3 -fPIC -Wall -c -o obj\L1_base.o SEcubeSources\L1\L1Base\L1_base.cpp
g++ -O3 -g3 -fPIC -Wall -c -o obj\L1_login_logout.o SEcubeSources\L1\L1_login_logout.cpp
g++ -O3 -g3 -fPIC -Wall -c -o obj\L1_security.o SEcubeSources\L1\L1_security.cpp
g++ -O3 -g3 -fPIC -Wall -c -o obj\L1.o SEcubeSources\L1\L1.cpp

g++ -O0 -g3 -fPIC -Wall -c -o obj\L0_wrapper.o L0_wrapper.cpp
g++ -O0 -g3 -fPIC -Wall -c -o obj\L1_wrapper.o L1_wrapper.cpp

g++ -shared -fPIC -o lib/SEcubeWrapper.dll ^
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
    obj\L0_wrapper.o ^
    obj\L1_wrapper.o
