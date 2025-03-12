check: build
	echo "15 characters." > 15char.txt
	echo "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum." > lipsum.txt
	curl https://github.com/cd-public/books/raw/main/pg1342.txt -o austen.txt 2>/dev/null
	# Makefile uses sh not bash so can't use <() and have to use the filesystem
	./shainc 15char.txt > 15char.inc
	./shainc lipsum.txt > lipsum.inc
	./shainc austen.txt > austen.inc
	sha256sum 15char.txt > 15char.sum
	sha256sum lipsum.txt > lipsum.sum
	sha256sum austen.txt > austen.sum
	diff 15char.inc 15char.sum || diff lipsum.inc lipsum.sum || diff austen.inc austen.sum


build:
	gcc shainc.c -Wall -Wextra -Werror -Wpedantic -O2 -o shainc

clean:
	rm shainc *.txt *.inc *.sum
