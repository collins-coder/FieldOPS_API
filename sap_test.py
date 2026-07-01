import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SAP_BASE_URL = "https://127.0.0.1:50000/b1s/v1"

SAP_LOGIN_PAYLOAD = {
    "CompanyDB": "TEST_DB",
    "UserName": "admin",
    "Password": "1234"
}


def sap_login():
    try:
        url = f"{SAP_BASE_URL}/Login"

        headers = {
            "Content-Type": "application/json"
        }

        response = requests.post(
            url,
            data=json.dumps(SAP_LOGIN_PAYLOAD),
            headers=headers,
            verify=False
        )

        if response.status_code == 200:
            return {
                "success": True,
                "session": response.cookies
            }

        return {
            "success": False,
            "error": response.text
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }