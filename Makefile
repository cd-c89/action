check: build
	/bin/bash tester.sh

build:
	gcc shainc.c -Wall -Wextra -Werror -Wpedantic -O2 -o shainc

clean:
	rm shainc *.txt
