#include "account.h"
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <check.h>

account_t *mock_account;

#test login_success
    // Test that a successful login updates the correct fields.
    mock_account = account_create("user1", "abc123", "a@example.com", "2000-01-01");
    ip4_addr_t ip = 0x7f000001; // 127.0.0.1
    account_record_login_success(mock_account, ip);
    ck_assert_int_eq(mock_account->login_count, 1);
    ck_assert_int_eq(mock_account->login_fail_count, 0);
    ck_assert_uint_ne(mock_account->last_login_time, 0);
    ck_assert_uint_eq(mock_account->last_ip, ip);
    account_free(mock_account);

#test login_failure
    // Test that a failed login updates the fail count and resets login count.
    mock_account = account_create("user2", "def456", "b@example.com", "2000-01-01");
    account_record_login_failure(mock_account);
    ck_assert_int_eq(mock_account->login_fail_count, 1);
    ck_assert_int_eq(mock_account->login_count, 0);
    account_free(mock_account);

#test login_success_null
    // Test that login success function handles NULL account without crashing.
    account_record_login_success(NULL, 0x7f000001);

#test login_failure_null
    // Test that login failure function handles NULL account without crashing.
    account_record_login_failure(NULL);

#test print_summary
    // Test that summary output works with a valid account and file descriptor.
    mock_account = account_create("user3", "ghi789", "c@example.com", "2000-01-01");
    mock_account->login_count = 5;
    mock_account->login_fail_count = 2;
    int fd = open("test_output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ck_assert_int_ne(fd, -1);
    bool result = account_print_summary(mock_account, fd);
    ck_assert(result == true);
    close(fd);
    account_free(mock_account);

#test print_summary_invalid_fd
    // Test that account_print_summary returns false for invalid file descriptor.
    mock_account = account_create("user4", "xyz", "x@example.com", "1999-12-31");
    bool result = account_print_summary(mock_account, -1);
    ck_assert(result == false);
    account_free(mock_account);

#test print_summary_null_account
    // Test that account_print_summary handles NULL input safely.
    bool result = account_print_summary(NULL, STDOUT_FILENO);
    ck_assert(result == false);

#test print_summary_invalid_ip
    // Test that invalid IP still allows summary to be written, with log warning.
    mock_account = account_create("user5", "p", "a@example.com", "2000-01-01");
    mock_account->last_ip = 0xffffffff + 1; // Invalid IPv4 (overflow)
    int fd = open("test_output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ck_assert_int_ne(fd, -1);
    bool result = account_print_summary(mock_account, fd);
    ck_assert(result == true); // Should still write successfully
    close(fd);
    account_free(mock_account);

#test print_summary_null_fields
    // Test that fallback strings are used when account fields are NULL or empty.
    mock_account = malloc(sizeof(account_t));
    memset(mock_account, 0, sizeof(account_t)); // All fields null/zeroed
    int fd = open("test_output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ck_assert_int_ne(fd, -1);
    bool result = account_print_summary(mock_account, fd);
    ck_assert(result == true); // Should print using "(unknown)" and "(none)"
    close(fd);
    free(mock_account);
