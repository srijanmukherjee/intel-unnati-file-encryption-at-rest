CPP=g++
CFLAGS=-Wall
LDFLAGS=`pkg-config --libs openssl`

enc: main.cpp file_cipher.cpp
	$(CPP) $(CFLAGS) $(LDFLAGS) -o enc file_cipher.cpp main.cpp