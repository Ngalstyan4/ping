
all: build run

build:
	gcc main.c -o ping

run:
	sudo ./ping am.am