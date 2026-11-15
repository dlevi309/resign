TARGET := resign

SRC    := src/codesign.m
LDLIBS := -framework Foundation -framework Security

SIGN   := ldid -Sent.xml
STRIP  := strip -rSx -no_code_signature_warning

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(LDFLAGS) $^ $(CFLAGS) $(LDLIBS) -o $@
	$(STRIP) $(TARGET)
	$(SIGN) $(TARGET)

clean:
	$(RM) $(TARGET)
