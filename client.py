import hashlib
import requests
from totp import TOTP

base_url = "http://127.0.0.1:5000"

# Parameters for TOTP
time_interval_sec = 30
digit_num = 6
hash_alg = hashlib.sha1

def post_request(root_path, json):
    response = requests.post(f"{base_url}{root_path}", json=json)
    if response.status_code >= 400:
        print(f"Error: Server returned {response.status_code}")

    # Check for a "too many requests" error
    resp_statcode = response.status_code
    resp_json = (
        response.json()
        if resp_statcode != 429
        else {"error": "Too many requests"}
    )

    return resp_json, resp_statcode

def register_user(username):
    response = post_request("/register", {"username": username})
    return response

def login(username, otp):
    return post_request("/login", {"username": username, "otp": otp})

if __name__ == "__main__":
    while True:
        print(
            "Actions:\n"
            "  Register     (r)\n"
            "  Login        (l)\n"
            "  Exit         (e)\n"
        )

        action = input("Choose action: ").strip().lower()

        match action:
            case "r":
                username = input("Enter username: ")
                if username:
                    print(register_user(username))
            case "l":
                username = input("Enter username: ")
                if username:
                    otp = input("Enter OTP: ")
                    if otp:
                        print(login(username, otp))
            case "e":
                print("Exitting...")
                break
            case _:
                print("Invalid action!")

        print()
