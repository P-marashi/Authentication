import random
from django.core.cache import cache
from datetime import datetime, timedelta


# in here we Generate OTP and set the params of that

def send_otp(mobile):
    last_request_time = cache.get(f"otp_request_time_{mobile}")
    if last_request_time and datetime.now() - last_request_time < timedelta(minutes=1):
        raise ValueError("Please wait for 1 minute before requesting another OTP.")
    else:
        otp = random.randint(1000, 9999)
        params = {
            'receptor': mobile,
            'token': otp,
            'template': "verify"
        }
        # code to send the OTP to the user's mobile number using your preferred method
        cache.set(mobile, otp, timeout=300)
        cache.set(f"otp_request_time_{mobile}", datetime.now(), timeout=60)
        return otp


# we check otp was sent to user with otp is in redis
def check_otp(mobile, otp):
    return str(cache.get(mobile)) == str(otp)
