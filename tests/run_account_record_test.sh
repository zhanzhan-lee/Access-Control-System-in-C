# Exit immediately if a command exits with a non-zero status.
set -e

echo "Generating C test file from account_record_test.ts..."
checkmk account_record_test.ts > account_record_test.c

echo "Compiling test program..."
gcc -o test_account_record account_record_test.c ../src/account.c ../src/stubs.c -I../src \
    -lcheck -lsubunit -lssl -lcrypto -lm -pthread -lrt


echo "Running unit tests..."
./test_account_record
 