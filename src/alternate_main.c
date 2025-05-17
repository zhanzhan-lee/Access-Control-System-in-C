#include <check.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include "account.h"
#include "login.h"
#include "logging.h"

int main() {
  // Simulated registration information
  const char *userid = "bob";
  const char *password = "securepassword";
  const char *email = "test@example.com";
  const char *birthdate = "2000-01-01";
  ip4_addr_t fake_ip = 0x7f000001; // 127.0.0.1
  time_t now = time(NULL);

  // Create a new account
  account_t *acc = account_create(userid, password, email, birthdate);
  if (!acc) {
    log_message(LOG_ERROR, "Failed to create account.");
    return 1;
  }

  // Simulate a login attempt
  login_session_data_t session;
  session.account_id = 0;
  session.session_start = 0;
  session.expiration_time = 0;

  // Test correct password login
  log_message(LOG_INFO, "\n--- Attempting login with correct password ---\n");
  login_result_t result1 = handle_login(
    userid, password, fake_ip, now,
    STDOUT_FILENO, &session
  );
  log_message(LOG_INFO, "Login result: %d (0 means success)\n", result1);

  if (result1 == LOGIN_SUCCESS) {
    log_message(LOG_INFO, "Session established:\n");
    log_message(LOG_INFO, "  account_id: %d\n", session.account_id);
    log_message(LOG_INFO, "  session_start: %ld\n", session.session_start);
    log_message(LOG_INFO, "  expiration_time: %ld\n", session.expiration_time);
  }

  // Test incorrect password login
  login_session_data_t session2 = {0};
  log_message(LOG_INFO, "\n--- Attempting login with WRONG password ---\n");
  login_result_t result2 = handle_login(
    userid, "wrongpassword", fake_ip, now,
    STDOUT_FILENO, &session2
  );
  log_message(LOG_INFO, "Login result: %d (should NOT be 0)\n", result2);

  account_free(acc);
  return 0;
}
