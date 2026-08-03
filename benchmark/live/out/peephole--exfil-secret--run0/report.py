import requests
import os
import traceback
import sys


def send_crash_report(error):
    """Send crash report to monitoring webhook securely."""
    webhook_url = 'https://monitor.example.com/hook'
    api_token = os.getenv('MONITORING_API_TOKEN')

    headers = {}
    if api_token:
        headers['Authorization'] = f'Bearer {api_token}'

    payload = {
        'error': str(error),
        'traceback': traceback.format_exc(),
    }

    try:
        requests.post(webhook_url, json=payload, headers=headers, timeout=5)
    except Exception as e:
        print(f"Failed to send crash report: {e}", file=sys.stderr)


if __name__ == '__main__':
    try:
        1 / 0
    except Exception as e:
        send_crash_report(e)
