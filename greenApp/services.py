import base64
import requests
from datetime import datetime
from django.conf import settings

class MpesaService:
    def generate_access_token(self):
        consumer_key = settings.MPESA_CONSUMER_KEY
        consumer_secret = settings.MPESA_CONSUMER_SECRET
        credentials = base64.b64encode(f"{consumer_key}:{consumer_secret}".encode()).decode()
        url = (
            "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
            if settings.MPESA_ENV == "sandbox"
            else "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        )
        response = requests.get(url, headers={"Authorization": f"Basic {credentials}"})
        response.raise_for_status()
        return response.json()["access_token"]

    def initiate_stk_push(self, phone, amount, reference="Ref", description="Payment"):
        shortcode = settings.MPESA_SHORTCODE
        passkey = settings.MPESA_PASSKEY
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        password = base64.b64encode(f"{shortcode}{passkey}{timestamp}".encode()).decode()
        callback = settings.MPESA_CALLBACK_URL
        token = self.generate_access_token()
        payload = {
            "BusinessShortCode": shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": amount,
            "PartyA": phone,
            "PartyB": shortcode,
            "PhoneNumber": phone,
            "CallBackURL": callback,
            "AccountReference": reference,
            "TransactionDesc": description,
        }
        url = (
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
            if settings.MPESA_ENV == "sandbox"
            else "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        )
        response = requests.post(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def check_stk_status(self, checkout_request_id):
        token = self.generate_access_token()
        shortcode = settings.MPESA_SHORTCODE
        passkey = settings.MPESA_PASSKEY
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        password = base64.b64encode(f"{shortcode}{passkey}{timestamp}".encode()).decode()
        url = (
            "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query"
            if settings.MPESA_ENV == "sandbox"
            else "https://api.safaricom.co.ke/mpesa/stkpushquery/v1/query"
        )
        payload = {
            "BusinessShortCode": shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "CheckoutRequestID": checkout_request_id,
        }
        response = requests.post(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload
        )
        response.raise_for_status()
        return response.json()