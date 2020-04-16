CC = gcc
CFLAGS =
PING = ping


# -lm is needed to link libm.so on linux
build: $(PING)

$(PING):
	$(CC) $(CFLAGS) main.c -o $(PING) -lm

run: $(PING)
	sudo $(PING) am.am

test: tests.sh $(PING)
	sudo bash tests.sh

testgen: tests.sh

tests.sh: testgen.py
	python testgen.py > tests.sh
