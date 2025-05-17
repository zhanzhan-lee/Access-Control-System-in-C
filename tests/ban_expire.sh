# Exit immediately if a command exits with a non-zero status.
set -e

echo "Generating C test file from ban_expire.ts..."
checkmk ban_expire.ts > ban_expire.c

echo "Compiling test program..."
gcc ban_expire.c ../src/account.c ../src/stubs.c -I../src \
    -o ban_expire \
    -lcheck -lsubunit -lssl -lcrypto -lm -pthread

echo "Running unit tests..."
./ban_expire
 
