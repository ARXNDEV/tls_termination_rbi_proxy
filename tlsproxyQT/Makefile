# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -g -fPIC -I/usr/include/qt -I/usr/include/x86_64-linux-gnu/qt5/QtCore -I/usr/include/x86_64-linux-gnu/qt5 -I/usr/include/x86_64-linux-gnu/qt5/QtNetwork

# Qt libraries to link against
LDFLAGS = -L/usr/lib/x86_64-linux-gnu -lQt5Core -lQt5Network -lssl -lcrypto

# Source and object files
SOURCES = main.cpp TlsClientConnection.cpp ConnectionHandler.cpp ProxyServer.cpp ProxyConnection.cpp TlsError.cpp ClientHello.cpp ClientHelloHandler.cpp CertificateCacheHandler.cpp
OBJECTS = $(SOURCES:.cpp=.o)

# MOC files
MOC_HEADERS = TlsClientConnection.h ConnectionHandler.h ProxyServer.h ProxyConnection.h TlsError.h ClientHello.h ClientHelloHandler.h CertificateCacheHandler.h
MOC_SOURCES = $(MOC_HEADERS:.h=.moc.cpp)
MOC_OBJECTS = $(MOC_SOURCES:.cpp=.o)

# Target executable
TARGET = tlsproxy

# Default target
all: $(TARGET)

# Link the executable with object files and MOC objects
$(TARGET): $(OBJECTS) $(MOC_OBJECTS)
	$(CXX) -o $(TARGET) $(OBJECTS) $(MOC_OBJECTS) $(LDFLAGS)

# Compile source files into object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Generate MOC files from headers
%.moc.cpp: %.h
	moc $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJECTS) $(MOC_OBJECTS) $(TARGET) $(MOC_SOURCES)

.PHONY: all clean
