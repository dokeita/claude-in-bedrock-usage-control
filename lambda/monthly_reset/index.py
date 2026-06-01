"""月初リセット Lambda: DynamoDB の利用量をリセットし、Deny ポリシーを削除"""
import os
import boto3

dynamodb = boto3.resource("dynamodb")
iam = boto3.client("iam")

TABLE_NAME = os.environ["USAGE_TABLE_NAME"]
DENY_POLICY_NAME = "BedrockUsageLimitDeny"

table = dynamodb.Table(TABLE_NAME)


def handler(event, context):
    # 全ユーザーをスキャンしてリセット
    response = table.scan()
    for item in response.get("Items", []):
        user_id = item["userId"]
        # Deny ポリシー削除
        if item.get("blocked"):
            username = user_id.split("/")[-1] if "/user/" in user_id else None
            if username:
                try:
                    iam.delete_user_policy(UserName=username, PolicyName=DENY_POLICY_NAME)
                except iam.exceptions.NoSuchEntityException:
                    pass
        # カウンターリセット
        table.update_item(
            Key={"userId": user_id},
            UpdateExpression="SET currentInputTokens = :z, currentOutputTokens = :z, "
                            "currentCostDollars = :zd, blocked = :f",
            ExpressionAttributeValues={":z": 0, ":zd": 0, ":f": False},
        )

    print(f"Reset {len(response.get('Items', []))} users")
