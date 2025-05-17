#include "account.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <time.h>
#include <arpa/inet.h>
#include "logging.h" 
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>


static int write_to_client(int client_output_fd, char *msg, size_t msg_size)
{
  size_t written = 0;
  ssize_t result;
  while (written < msg_size) {
    result = write(client_output_fd, msg + written, msg_size - written);
    if (result == -1) {
      if (errno == EINTR) {
        continue;
      }
      else {
        log_message(LOG_ERROR, "Call to write() failed.");
        return 1;
      }
    }
    written += (size_t) result;
  }
  return 0;
}
bool hex_to_bytes(const char *hex, uint8_t *out) {
  for (int i = 0; i < 16; i++) {
      if (sscanf(&hex[i * 2], "%2hhx", &out[i]) != 1) {
          return false;
      }
  }
  return true;
}

/**
 * Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 *
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 */
bool validate_email(const char *email) {
  const char *at_ptr = NULL;
  //Ensures emails exceeding character length are invalidated first before iterating through each character
  if (strlen(email) >= EMAIL_LENGTH) {
    log_message(LOG_WARN,"Invalid email: The number of characters exceeds maximum limit.");
    return false;
  }
  //Checks for spaces,non-printable characters & returns false
  for(size_t i = 0; email[i] != '\0'; i++) {
    if(email[i] < 32 || email[i] > 126 || email[i] == ' ') {
      log_message(LOG_WARN,"Invalid email: contains non-printable characters or spaces");
      return false;
    }
  }
  return true;
}

//Validate birthdate function
bool validate_birthdate(const char *birthdate) {
  if (strlen(birthdate) != BIRTHDATE_LENGTH) {
    log_message(LOG_WARN,"Invalid birthdate: length is not 10 characters and in YYYY-MM-DD format");
    return false;
  }
  if (birthdate[4] != '-' || birthdate[7] != '-') { //Invalidates birthdates with missing dashes
    log_message(LOG_WARN,"Invalid birthdate: dashes are missing from supplied birthdate");
    return false;
  }
  for (int i = 0; i < 10; i++) {
    if (i == 4 || i == 7) continue;
    if (!isdigit(birthdate[i])) { //Ensures that all characters are digits, excluding dashes
      log_message(LOG_WARN,"Invalid birthdate: contains non-digit characters");
      return false;
    }
  }
  return true;
}

bool generate_hash(const char *plaintext_password, char *hash, size_t hash_length) {
  unsigned char salt[16];
  unsigned char hash_buffer[16];

  //Generates a random salt to ensure every password hash is unique - prevents rainbow table attacks
  if (RAND_bytes(salt, sizeof(salt)) != 1) {
    log_message(LOG_ERROR,"Failed to generate random salt.");
    return false;
  }

  //Hash the password using PBKDF2 with HMAC-SHA256
  //We could increase the iterations here**** eg(10,000)
  if (PKCS5_PBKDF2_HMAC(plaintext_password, strlen(plaintext_password),salt,sizeof(salt),1000, EVP_sha256(),16,hash_buffer) != 1) {
    log_message(LOG_ERROR,"Failed to hash password.");
    return false;
  }

  //Converts salt,hash into a 2 character hexadecimal string and combines using ':' as the seperator
  char combined_hex[2 * (16 + 16) + 2];
  char *write_ptr = combined_hex;

  for (size_t i = 0; i < sizeof(salt); i++) {
    snprintf(write_ptr,3,"%02x",salt[i]);
    write_ptr += 2; //Use of snprintf prevents buffer overflow ensuring safe writing to the buffer
  }

  *write_ptr++ = ':';
  for (size_t i = 0; i < sizeof(hash_buffer); i++) {
    snprintf(write_ptr,3,"%02x",hash_buffer[i]);
    write_ptr += 2;
  }

  *write_ptr = '\0'; //Null-terminate the hash string

  if (strlen(combined_hex) >= hash_length) {
    log_message(LOG_ERROR,"Combined hash exceeds hash buffer size");
    return false;
  }
  strncpy(hash,combined_hex,hash_length); //Copy the combined hash into the provided buffer safely after confirming buffer size

  return true;
}


account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate)
{
  // Uses the the struct and dynamically allocates it using malloc
  account_t *new_user = malloc(sizeof(account_t));
  //Allocate memory for the new account and check that it was successful to avoid memory leaks
  if (new_user == NULL) {
   log_message(LOG_ERROR,"Memory allocation for the new user account has failed");
   return NULL;
   }
  if(!validate_email(email) || !validate_birthdate(birthdate)) {
   log_message(LOG_ERROR,"Validation Error:Invalid email or birthdate.");
   free(new_user); //Free allocated memory to prevent memory leaks for failed cases
   return NULL;
  }

  if(strlen(userid) >= USER_ID_LENGTH) {
   log_message(LOG_ERROR,"Validation Error: User id supplied exceeds maximum length");
   free(new_user);
   return NULL;

  }
  //Generate encoded password hash
  char hash_buffer[HASH_LENGTH]; //Use a buffer to store the hash safely; prevents buffer overflow
  if (!generate_hash(plaintext_password,hash_buffer,sizeof(hash_buffer))) {
      log_message(LOG_ERROR,"Failed to generate password hash.");
      free(new_user);
      return NULL;
  }
  //Strncpy copies the string into the new_user struct and ensures that the string is null-terminated
  //Explicitly null-terminate the last position in the string in the case where the lengths are equal
  strncpy(new_user->userid,userid,USER_ID_LENGTH - 1);
  new_user->userid[USER_ID_LENGTH - 1] = '\0';

  strncpy(new_user->email, email,EMAIL_LENGTH - 1);
  new_user->email[EMAIL_LENGTH - 1] = '\0';

  strncpy(new_user->birthdate,birthdate,BIRTHDATE_LENGTH - 1);
  new_user->birthdate[BIRTHDATE_LENGTH - 1] = '\0';

  strncpy(new_user->password_hash,hash_buffer,HASH_LENGTH - 1);
  new_user->password_hash[HASH_LENGTH - 1] = '\0';

  //Set the other default fields to 0
  new_user->unban_time = 0;
  new_user->expiration_time = 0;
  new_user->login_count = 0;
  new_user->login_fail_count = 0;
  new_user->last_login_time = 0;
  new_user->last_ip = 0;

  return new_user;
}

void account_free(account_t *acc) {
     if(acc != NULL) {
      free(acc);
     }
}

bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  log_message(LOG_DEBUG, "\n[ account_validate_password() ] starting\n");

  if (acc == NULL){
    // acc arguement is null
    log_message(LOG_DEBUG,"[account_update_password()] ERROR: acc is NULL\n");
    return false;
  }

  if (plaintext_password == NULL){
    // new_plaintext_password is null
    log_message(LOG_DEBUG, "[account_update_password()] ERROR: plaintext_password is NULL\n");
    return false;
  }

  // for reading the correct passcode off the struct
  char salt_hex[33], hash_hex[33];
  // unvalidated passcode is SHA256(plaintext_passcode)
  // validated passcode is hash_hex converted into byte code
  unsigned char unvalidated_password[16];
  unsigned char validated_password[16];

  // both the plaintext password and correct password must have same salt when computing hash
  unsigned char salt[16];

  // find ':' in acc->password_hash
  const char* seperator = strchr(acc->password_hash, ':');

  // 32 because hex doubles the size of bytecode because its a string / 32 hex string = 16 bytes
  memcpy(salt_hex, acc->password_hash, 32);
  salt_hex[32] = '\0';

  // Securely copy the hash (next 32 bytes after the separator)
  //memcpy(hash_hex, separator+1, 32); // THIS LINE CAUSES A SEGFAULT WITH THE CURRENT TEST CASE
  memcpy(hash_hex, acc->password_hash + 33, 32); // TEMP FIX

  hash_hex[32] = '\0';

  log_message(LOG_DEBUG, "[ account_validate_password() ] converting recorded salt and hash from hex to bytecode\n");
  hex_to_bytes(salt_hex, salt);
  hex_to_bytes(hash_hex, validated_password);

  log_message(LOG_DEBUG, "[ account_validate_password() ] computing SHA256() of plaintext_password\n");
  PKCS5_PBKDF2_HMAC(plaintext_password, strlen(plaintext_password), salt, sizeof(salt), 1000, EVP_sha256(), 16, unvalidated_password);

  if (CRYPTO_memcmp(validated_password, unvalidated_password, sizeof(validated_password)) == 0) {
    log_message(LOG_DEBUG, "[ account_validate_password() ] correct password\n");
    return true; // Password is correct
  }
  else {
    log_message(LOG_DEBUG, "[ account_validate_password() ] incorrect password\n");
    return false; // Password is incorrect
  }
  return false;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {

  log_message(LOG_DEBUG, "\n[ account_update_password() ] starting\n");

  unsigned char salt[16];
  unsigned char hash[16];

  if (acc == NULL){
    // acc arguement is null
    log_message(LOG_DEBUG, "[ account_update_password() ] ERROR: acc is NULL\n");
    return false;
  }

  if (new_plaintext_password == NULL){
    // new_plaintext_password is null
    log_message(LOG_DEBUG, "[ account_update_password() ] ERROR: new_plaintext_password is NULL\n");
    return false;
  }

  if (RAND_bytes(salt, sizeof(salt))){
    // successfully created a salt
    // source: https://docs.openssl.org/1.0.2/man3/RAND_bytes/

    log_message(LOG_DEBUG, "[ account_update_password() ] successfully created a salt\n");
  }
  else {
    // error created a salt using RAND_bytes()
    // source: https://docs.openssl.org/1.0.2/man3/RAND_bytes/

    log_message(LOG_DEBUG, "[ account_update_password() ] ERROR: RAND_bytes() function failed\n");
    return false;
  }
  
  log_message(LOG_DEBUG, "[ account_update_password() ] computing SHA256() hash\n");
  PKCS5_PBKDF2_HMAC(new_plaintext_password, strlen(new_plaintext_password), salt, sizeof(salt), 1000, EVP_sha256(), 16, hash);

  // convert salt to a hex string ended with a ':'
  // get the fist part of the password_hash address and edit each byte
  char *pointer_password_hash = acc->password_hash;
  for (size_t index = 0; index < sizeof(salt); index++) {
    pointer_password_hash += sprintf(pointer_password_hash, "%02x", salt[index]);
  }

  // now adding the semi colon to split into salt:hash
  *pointer_password_hash++ = ':';

  // convert hash to a hex string 
  for (size_t index = 0; index < sizeof(hash); index++)
    pointer_password_hash += sprintf(pointer_password_hash, "%02x", hash[index]);

  // null terminate the entire hash
  *pointer_password_hash = '\0';

  log_message(LOG_DEBUG, "[ account_update_password() ] full computed hash with salt = ");
  log_message(LOG_DEBUG, "%s\n", acc->password_hash);  // use 16 for 128-bit hash
  return true;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  if (!acc) return;

  acc->login_count += 1;
  acc->login_fail_count = 0;
  acc->last_login_time = time(NULL);
  acc->last_ip = ip;
  // Log the successful login
  log_message(LOG_INFO, "User %s login SUCCESS from IP: %u", acc->userid, ip);
}

void account_record_login_failure(account_t *acc) {
  if (!acc) return;

  acc->login_fail_count += 1;
  acc->login_count = 0;
  // Log the failed login attempt
  log_message(LOG_WARN, "User %s login FAILURE (fail count = %u)",acc->userid, acc->login_fail_count);
}

bool account_is_banned(const account_t *acc) {
	time_t current_time = time(NULL); // gets the current time
	return acc->unban_time != 0 && current_time < acc->unban_time; //checks if unban_time is not zero (aka never banned) and if the current time is less than the unban_time
}

bool account_is_expired(const account_t *acc) {
	time_t current_time = time(NULL); //gets current time
	return acc->expiration_time != 0 && acc->expiration_time < current_time; //same as account_is_banned, but checks if current time is greater instead
}

void account_set_unban_time(account_t *acc, time_t t) {
	if (t < 0) { //input sanitisation for time
		log_message(LOG_ERROR, "Failed to set an unban time. Please use a non-negative time value.");
		return;
	}

	acc->unban_time = time(NULL) + t; //rewrites unban_time to be current time + whatever extra ban time specified as t
	log_message(LOG_INFO, "User %s successfully banned for %ld seconds, set to expire at %ld",acc->userid, t, acc->unban_time); //log message with length of ban and when it expires
}

void account_set_expiration_time(account_t *acc, time_t t) {
	if (t < 0) { //input sanitisation for time
		log_message(LOG_ERROR, "Failed to set an expiration time. Please use a non-negative time value");
		return;
	}

	acc->expiration_time = time(NULL) + t; //rewrites expiration_time to be current time + extra time specified in t
	log_message(LOG_INFO, "User %s's expiration time changed to %ld",acc->userid, acc->expiration_time); //log message with new expiration date
}

void account_set_email(account_t *acc, const char *new_email) {
  if(!validate_email(new_email)) {
    log_message(LOG_WARN,"Failed to set email, for USER ID: %s - invalid email: %s ",acc->userid,new_email);
    return;
  }
  strncpy(acc->email,new_email,EMAIL_LENGTH - 1);
  acc->email[EMAIL_LENGTH - 1] = '\0';
  log_message(LOG_INFO,"The email address for USER ID: %s, has been changed to %s", acc->userid,acc->email);
}

bool account_print_summary(const account_t *acct, int fd) {
  if (!acct || fd < 0) return false;

  char timebuf[64] = "N/A";
  struct tm *tm_info = localtime(&(acct->last_login_time));
  if (tm_info) {
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
  }

  char ipbuf[INET_ADDRSTRLEN] = "N/A";
  struct in_addr ip_addr = { acct->last_ip };
  if (!inet_ntop(AF_INET, &ip_addr, ipbuf, sizeof(ipbuf))) {
    log_message(LOG_WARN, "Failed to format IP address for user %s",
                acct->userid ? acct->userid : "(null)");
  }

  const char *uid = acct->userid ? acct->userid : "(unknown)";
  const char *email = acct->email ? acct->email : "(none)";

  char buffer[512];
  int written = snprintf(buffer, sizeof(buffer),
    "User ID: %s\n"
    "Email: %s\n"
    "Login Count: %u\n"
    "Login Fail Count: %u\n"
    "Last Login Time: %s\n"
    "Last IP: %s\n",
    uid, email, acct->login_count, acct->login_fail_count, timebuf, ipbuf
  );

  if (written < 0 || written >= sizeof(buffer)) {
    log_message(LOG_ERROR, "Summary output truncated or failed.");
    return false;
  }

  if (write_to_client(fd, buffer, written)) {
    log_message(LOG_ERROR, "Failed to write summary to client.");
    return false;
  }

  return true;
}

