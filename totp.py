import base64
import hashlib
import hmac
import os
import struct
import time

class TOTP:
    def __init__(self, secret: str, time_interval_sec: int = 30,
            digit_num: int = 6, hash_alg=hashlib.sha1):
        """
        Initialize TOTP instance
        :param secret: Base32 encoded secret key
        :param time_interval_sec: Time step in seconds (default 30s)
        :param digit_num: Number of OTP digits (default 6)
        :param hash_alg: Hashing algorithm (default SHA1)
        """
        # Store the secret decoded (bytes)
        self.secret = base64.b32decode(secret, casefold=True)

        self.time_interval_sec = time_interval_sec
        self.digit_num = digit_num
        self.hash_alg = hash_alg

    def _counter(self):
        # Compute the 8 byte counter
        # Floor division of the current time with the time_interval_sec
        return int(time.time()) // self.time_interval_sec & 0xFFFFFFFFFFFFFFFF

    def _generate_otp(self, counter: int) -> str:
        """
        Implementing the algorithm of TOTP as described in RFC 6238, which is
        based on the algorithm of HOTP as described in RFC 4226.
        """
        # Convert the counter from int to bytes (big-endian, unsigned long
        # long)
        counter_bytes = struct.pack(">Q", counter)

        # Get the HMAC hash of the secret and the counter
        hmac_hash = hmac.digest(self.secret, counter_bytes, self.hash_alg)

        # The offset is an unsigned int (i.e., in [0, 15]) derived from the
        # low-order 4 bits of the last byte of the HMAC hash
        offset = hmac_hash[-1] & 0x0F

        # The dynamic truncation result is the last 31 bits of
        # hmac_hash[offset:offset+4]
        dt_result = (
            struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
        )

        # The OTP to be returned is dt_result % 10**digit_num
        otp = dt_result % 10**self.digit_num

        # Pad with zeros if needed to match the number of digits
        return str(otp).zfill(self.digit_num)

    def get_current_otp(self) -> str:
        # Get the counter based on the current time
        return self._generate_otp(self._counter())

    def verify_otp(self, otp: str, drift: int = 0) -> bool:
        # Except from checking just the current time window, also check some
        # time windows around it in case there is a time desynchronization
        current_counter = self._counter()
        for counter_offset in range(-drift, drift + 1):
            if self._generate_otp(current_counter + counter_offset) == otp:
                return True
        return False


# Simple immediate testing
if __name__ == '__main__':
    secret = base64.b32encode(b'ABC').decode()
    totp_obj = TOTP(secret)

    otp = totp_obj.get_current_otp()
    print(otp)

    otp = input('Type the OTP: ')
    verified = totp_obj.verify_otp(otp)
    print(f'Verified: {verified}')

