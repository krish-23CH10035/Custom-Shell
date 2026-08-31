CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic
LDFLAGS = -lcrypto

TARGET = mysh
SOURCE = src/main.cpp

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) $(SOURCE) -o $(TARGET) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean