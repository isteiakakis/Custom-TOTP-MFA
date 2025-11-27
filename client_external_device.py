import hashlib
import time
from totp import TOTP

"""
Simulates an external device.
Given a secret, it continuously prints the current OTP.
"""

# Parameters for TOTP
time_interval_sec = 30
digit_num = 6
hash_alg = hashlib.sha1

# Get the user secret
secret = input("Enter the shared secret (base32): ")

# Create a TOTP object using the stored user secret
totp_handle = TOTP(secret, time_interval_sec=time_interval_sec,
        digit_num=digit_num, hash_alg=hash_alg)

while True:
    # Generate the current OTP and print it
    otp = totp_handle.get_current_otp()
    print(otp)
    time.sleep(.5)


