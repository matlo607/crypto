CC=g++
INCFLAGS= -I../include
CXXFLAGS= -g -std=c++14 -W -Wall -Werror
LDFLAGS= -lgtest -lgtest_main -lpthread

SRC:= $(wildcard *.cpp)
SRC:= $(wildcard ../src/*.cpp)
OBJ:= $(SRC:.cpp=.o)

all: test_libcrypto

INCLUDE_FILES=../include/*.hpp ../include/*.ipp

MD4.o: ../src/MD4.cpp $(INCLUDE_FILES)
MD5.o: ../src/MD5.cpp $(INCLUDE_FILES)
SHA1.o: ../src/SHA1.cpp $(INCLUDE_FILES)
SHA224.o: ../src/SHA224.cpp $(INCLUDE_FILES)
SHA256.o: ../src/SHA256.cpp $(INCLUDE_FILES)
test_libcrypto.o: test_libcrypto.cpp $(INCLUDE_FILES)

%.o: %.cpp
	$(CC) $(CXXFLAGS) $(INCFLAGS) -c $< -o $@

test_libcrypto: test_libcrypto.o ../src/SHA1.o ../src/MD5.o ../src/MD4.o ../src/SHA224.o ../src/SHA256.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf *.o ../src/*.o test_libcrypto

