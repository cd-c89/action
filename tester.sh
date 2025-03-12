gcc shainc.c --std=c89 -Wall -Wextra -Werror -Wpedantic -O2 -o shainc
echo "15 characters." > 15char.txt
echo "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum." > lipsum.txt
curl https://github.com/cd-public/books/raw/main/pg1342.txt -o austen.txt 2>/dev/null
echo " === Finding errors vs. reference implementation. === "
diff <(sha256sum 15char.txt) <(./shainc 15char.txt)
diff <(sha256sum lipsum.txt) <(./shainc lipsum.txt)
diff <(sha256sum austen.txt) <(./shainc austen.txt)
echo " === Errors printed. No errors denotes \"Perfect!\" === "