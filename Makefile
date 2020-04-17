CC = gcc
CFLAGS =
PING = ./ping


# -lm is needed to link libm.so on linux
$(PING): main.c
	$(CC) $(CFLAGS) main.c -o $(PING) -lm

run: $(PING)
	sudo $(PING) am.am

test: tests.sh $(PING)
	sudo bash tests.sh

testgen: tests.sh

tests.sh: testgen.py
	python testgen.py > tests.sh

setuidlinux:
	sudo chown root:root $(PING)
	sudo chmod u+s $(PING)

setuidmac:
	sudo chown root:wheel $(PING)
	sudo chmod u+s $(PING)