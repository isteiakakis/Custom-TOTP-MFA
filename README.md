# Custom-TOTP-MFA
Custom Time-based One-Time Password (TOTP) Multi-Factor Authentication (MFA)

## Usage
* Run the server.
* Run the client.
* When registering a user, a secret is returned to the client.
* Run the external client device with the returned secret to get the (constantly updating) current TOTP value.
* Perform the login in client.
