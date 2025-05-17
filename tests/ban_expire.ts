#define CITS3007_PERMISSIVE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>

#include "account.h"

#define ARR_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#suite account_suite

#tcase account_is_banned_test_case

#test test_account_is_banned_cases
//tests to see if an account is banned
  account_t acc = {0};

  acc.unban_time = 0;
  ck_assert_int_eq(account_is_banned(&acc), 0);

  acc.unban_time = time(NULL) + 3600;
  ck_assert_int_eq(account_is_banned(&acc), 1);

  acc.unban_time = time(NULL) - 3600;
  ck_assert_int_eq(account_is_banned(&acc), 0);


#tcase account_is_expired_test_case

#test test_account_is_expired_cases
//tests to see if an account is expired
  account_t acc = {0};

  acc.expiration_time = 0;
  ck_assert_int_eq(account_is_expired(&acc), 0);

  acc.expiration_time = time(NULL) + 3600;
  ck_assert_int_eq(account_is_expired(&acc), 0);

  acc.expiration_time = time(NULL) - 3600;
  ck_assert_int_eq(account_is_expired(&acc), 1);


#tcase account_set_unban_time_test_case

#test test_account_set_unban_time_cases
//tests whether the function behind setting bans and unbans actually works
  account_t acc = {0};

  time_t now = time(NULL);
  account_set_unban_time(&acc, 3600);
  ck_assert_int_le(abs((int)(acc.unban_time - now - 3600)), 1);

  now = time(NULL);
  account_set_unban_time(&acc, 0);
  ck_assert_int_le(abs((int)(acc.unban_time - now)), 1);

  now = time(NULL);
  account_set_unban_time(&acc, 86400);
  ck_assert_int_le(abs((int)(acc.unban_time - now - 86400)), 1);


#tcase account_set_expiration_time_test_case

#test test_account_set_expiration_time_cases
//tests whether function behind setting expiration time works
  account_t acc = {0};

  time_t now = time(NULL);
  account_set_expiration_time(&acc, 3600);
  ck_assert_int_le(abs((int)(acc.expiration_time - now - 3600)), 1);

  now = time(NULL);
  account_set_expiration_time(&acc, 0);
  ck_assert_int_le(abs((int)(acc.expiration_time - now)), 1);

  now = time(NULL);
  account_set_expiration_time(&acc, 2592000);
  ck_assert_int_le(abs((int)(acc.expiration_time - now - 2592000)), 1);

// vim: syntax=c :

