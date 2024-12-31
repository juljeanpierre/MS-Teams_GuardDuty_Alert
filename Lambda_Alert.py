import os
import json
import urllib3

# Get the MS-TEAMs environment variable
teams_webhook_url = os.environ['HookUrl']

# Account List
your_accounts = ''' {
    "accounts": [{
        "name": "ACCOUNT_NAME",
        "id": "123456789012"
    }
    ]
}
'''
account_data = json.loads(your_accounts)
def lambda_handler(event, context):
    # Extract the finding from the event data
    if isinstance(event['detail'], str):
        finding = json.loads(event['detail'])

    else:
        finding = event['detail']
    print(finding)
    severity = finding['severity']

    # Only send alerts for Medium and greater severity events
    if severity >= 4.0:
        # Extract the required fields
        account_id = finding['accountId']
        for account in account_data['accounts']:
            if account['id'] == account_id:
                account_id = account['id'], account['name']

        # Get the region
        region = event['region']

        title = (
        f"AWS GuardDuty Finding in {account_id}"
        )

        # Define the message to be sent to MS-Teams
        message = {
                "@context": "https://schema.org/extensions",
                "@type": "MessageCard",
                "themeColor": "85dbe1",
                "title": title,
                "text": f"{finding['description']}",
                "sections": [
                    {
                        "facts": [
                            {
                                "name": "Type: ",
                                "value": f"{finding['type']}"
                            },
                            {
                                "name": "Severity: ",
                                "value": f"{severity}"
                            },
                            {
                                "name": "Region: ",
                                "value": f"{region}"
                            }
                        ]
                    }
                ]
            }
        # Convert message to JSON string
        message_json = json.dumps(message)

        # Send the message to MS-Teams using urllib3
        http = urllib3.PoolManager()
        try:
            response = http.request('POST', teams_webhook_url, body=message_json.encode('utf-8'),
                                    headers={'Content-Type': 'application/json'})
            if response.status != 200:
                raise Exception(f"Failed to send message to Microsoft Teams: {response.status}")
        except Exception as e:
            # Handle exception here
            print(f"Failed to send message to MS-Teams: {e}")
    return 'Success'