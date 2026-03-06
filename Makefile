CC = gcc

SYSLOG_DIR = /home/tanner/rsyslog
CFLAGS = -fPIC \
	-I$(SYSLOG_DIR) \
	-I$(SYSLOG_DIR)/runtime \
	-I$(SYSLOG_DIR)/grammar \
	-I$(SYSLOG_DIR)/tools \
	-I$(SYSLOG_DIR)/plugins \
	-I/usr/include/libxml2 \
	-I/usr/include/json-c \
	$(shell pkg-config --cflags libxml-2.0 libcurl)

LDFLAGS = -shared \
	$(shell pkg-config --libs libxml-2.0 libcurl) \
	-luuid

TARGET = omjalop.so
SRC = omjalop.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
	rm -rf jalop_records

.PHONY: all clean