import requests
import json

def send_sales_order(order_data):
    try:
        

        fake_response = {
            "DocEntry": 1001,
            "message": "Sales Order Created Successfully"
        }

        return {
            "success": True,
            "response": fake_response
        }

    except Exception as e:
        return {
            "success": False,
            "response": str(e)
        }