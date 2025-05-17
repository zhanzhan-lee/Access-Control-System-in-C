#include "login.h"
#include "logging.h"

#include <unistd.h>

// From stubs.c
bool account_lookup_by_userid(const char *userid, account_t *acc);

/**
 * Attempts to write() to the client file descriptor.
 * 
 * On write() success, returns 0.
 * On write() failure, logs an appropriate message and returns 1.
 * 
 * \param client_output_fd  Open and writtable file descriptor to send message 
 *                          to client
 * \param msg               Null-terminated string containing message to send 
 *                          to client
 * \param msg_size          The number of bytes required to store msg
 */
int write_to_client(int client_output_fd, char *msg, size_t msg_size) 
{
  ssize_t write_result = write(client_output_fd, msg, msg_size);
  
  if (write_result == -1) { 
    log_message(LOG_ERROR, "Call to write() failed.");
    return 1; 
  }
  
  /* write_result is a number of bytes and thus can be safely converted 
  into an unsigned type to avoid any errors with comparing to msg_size */ 
  size_t bytes_written = (size_t) write_result; 

  if (bytes_written != msg_size) {
    log_message(LOG_ERROR, "Call to write() resulted in a partial write.");
    return 1; 
  }
  
  return 0;
}

/**
 * Handles sending of output to client, recording login result to account, 
 * logging a message containing the login result and userid of user who
 * made the login attempt. 
 * 
 * On success, records login result and returns the login_result_t 
 * specificed by login_result.
 * 
 * On failure, does NOT record login result, and returns 
 * LOGIN_FAIL_INTERNAL_ERROR.
 * 
 * Should be called after idenitfying the appropriate login_result_t to return.
 * 
 * \param userid            The null-terminated string containing the userid
 * \param acc               A poitner to a valid account_t struct
 * \param client_ip         IPv4 address of the client
 * \param client_output_fd  Open and writable file descriptor used to send 
 *                          message to client
 * \param client_msg        The string to send to the client
 * \param client_msg_size   The number of bytes required to store client_msg
 * \param login_result      A login_result_t specifying which login result value 
 *                          to return on wrte() success
 * \param log_msg           A string containing exactly one "%s" to insert the 
 *                          userid into
 * 
 */
login_result_t handle_login_result(const char *userid, account_t *acc,
                         ip4_addr_t client_ip, int client_output_fd,
                         char* client_msg, size_t client_msg_size,
                         login_result_t login_result, char* log_msg) 
{
  if (write_to_client(client_output_fd, client_msg, client_msg_size)) {
    log_message(LOG_INFO, "LOGIN FAILED INTERNAL ERROR: user_id: %s\n");
    return LOGIN_FAIL_INTERNAL_ERROR;
  }
  
  if (login_result == LOGIN_SUCCESS) {
    account_record_login_success(acc, client_ip);
  }
  else {
    account_record_login_failure(acc);
  }
  
  log_message(LOG_INFO, log_msg, userid);
  return login_result;
}

// Refer to login.h for documentation
login_result_t handle_login(const char *userid, const char *password,
                            ip4_addr_t client_ip, time_t login_time,
                            int client_output_fd,
                            login_session_data_t *session)
{
  account_t acc;
  log_message(LOG_INFO, "ATTEMPTING LOGIN: userid = %s\n", userid);
  /*
    For defining client messages for all of the below:

    Init msg as a char array (NOT A CHAR POINTER) so it's size is defined 
    at compile time enabling sizeof() to return it's number of bytes 
    before passing.
    
    Size cannot be determined after passing as sizeof() cannot determine
    size of array from a pointer to the array.
  */ 
  if (!account_lookup_by_userid(userid, &acc)) {
    char msg[] = "Login failed. Incorrect username.";
    size_t msg_size = sizeof(msg);
    return handle_login_result(userid, &acc, client_ip, client_output_fd, 
                              msg, msg_size, LOGIN_FAIL_USER_NOT_FOUND, 
                              "LOGIN FAIL USER NOT FOUND: user_id = %s\n");
  }
  log_message(LOG_DEBUG, "LOGIN USERID OK");
  if (account_is_banned(&acc)) {
    char msg[] = "Login failed. Account is banned."; 
    size_t msg_size = sizeof(msg);
    return handle_login_result(userid, &acc, client_ip, client_output_fd, 
                              msg, msg_size, LOGIN_FAIL_ACCOUNT_BANNED, 
                              "LOGIN FAIL ACCOUNT BANNED: user_id = %s\n");
  }
  log_message(LOG_DEBUG, "LOGIN BANNED OK");
  if (account_is_expired(&acc)) {
    char msg[] = "Login failed. Account has expired."; 
    size_t msg_size = sizeof(msg);
    return handle_login_result(userid, &acc, client_ip, client_output_fd, 
                              msg, msg_size, LOGIN_FAIL_ACCOUNT_EXPIRED, 
                              "LOGIN FAIL ACCOUNT EXPIRED: user_id = %s\n");
  }
  log_message(LOG_DEBUG, "LOGIN EXPIRED OK");
  if (acc.login_fail_count > 10) {
    char msg[] = "Login failed. Exceeded maximum failed login attempts."; 
    size_t msg_size = sizeof(msg);
    return handle_login_result(userid, &acc, client_ip, client_output_fd, 
                              msg, msg_size, LOGIN_FAIL_IP_BANNED, 
                              "LOGIN FAIL IP BANNED: user_id = %s\n");
  }
  log_message(LOG_DEBUG, "LOGIN ATTEMPTS OK");
  if (!account_validate_password(&acc, password)) {
    char msg[] = "Login failed. Incorrect password."; 
    size_t msg_size = sizeof(msg);
    return handle_login_result(userid, &acc, client_ip, client_output_fd, 
                              msg, msg_size, LOGIN_FAIL_BAD_PASSWORD, 
                              "LOGIN FAIL BAD PASSWORD: user_id = %s\n");
  }
  log_message(LOG_DEBUG, "LOGIN PASSWORD OK");
  
  char msg[] = "Login successful.";
  size_t msg_size = sizeof(msg);
  login_result_t login_result = handle_login_result(userid, &acc, client_ip, 
                              client_output_fd, msg, msg_size, LOGIN_SUCCESS, 
                              "LOGIN SUCCESS: user_id: %s\n");
  
  if (login_result == LOGIN_SUCCESS) { 
    /* Conversion from long int to int here seems wrong but both types are 
    defined in the provided header files thus cannot be changed. */
    session->account_id = (int) acc.account_id;     
    session->session_start = login_time;
    session->expiration_time = acc.expiration_time;
  }
  return login_result;
}
