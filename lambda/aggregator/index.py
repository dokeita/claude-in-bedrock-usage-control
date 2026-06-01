"""集計 Lambda: S3 の Bedrock invocation log からユーザー毎のトークン数を集計。
閾値超過時に IAM Deny + SNS 通知。"""
import gzip
import json
import os
from datetime import datetime, timedelta, timezone

import boto3

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
iam = boto3.client("iam")

TABLE_NAME = os.environ["USAGE_TABLE_NAME"]
BUCKET_NAME = os.environ["LOG_BUCKET_NAME"]
TOPIC_ARN = os.environ["ALERT_TOPIC_ARN"]
TOKEN_LIMIT = int(os.environ["MONTHLY_TOKEN_LIMIT"])

DENY_POLICY_NAME = "BedrockUsageLimitDeny"
DENY_POLICY_DOC = json.dumps({
    "Version":
    "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": ["bedrock:InvokeModel*", "bedrock:Converse*"],
        "Resource": "*",
    }]
})

table = dynamodb.Table(TABLE_NAME)

# 処理済みファイル管理用のキー
PROCESSED_KEY = "__processed_files__"


def handler(event, context):
    # full_scan モード: 当月全件スキャンしてDynamoDBを上書き
    if event.get("full_scan"):
        return handle_full_scan()

    now = datetime.now(timezone.utc)
    start_time = now - timedelta(minutes=16)
    print(
        f"[handler] start_time={start_time.isoformat()}, end_time={now.isoformat()}"
    )

    # 処理済みファイル一覧を取得
    processed_files = get_processed_files()
    print(f"[handler] already processed: {len(processed_files)} files")

    # S3 invocation log から未処理ファイルのみ集計
    user_tokens, new_files = aggregate_from_s3_logs(start_time,
                                                    processed_files)
    print(
        f"[handler] aggregate result: {len(user_tokens)} users, new_files={len(new_files)}, data={user_tokens}"
    )

    # DynamoDB 更新 + 閾値チェック
    for user_id, tokens in user_tokens.items():
        print(f"[handler] update_and_check user={user_id}, tokens={tokens}")
        update_and_check(user_id, tokens)

    # 処理済みファイルを記録
    if new_files:
        save_processed_files(processed_files | new_files)


def handle_full_scan():
    """当月のS3ログを全件スキャンし、DynamoDBのトークン数を上書き"""
    now = datetime.now(timezone.utc)
    print(f"[full_scan] Starting full scan for {now.strftime('%Y/%m')}")

    account_id = boto3.client("sts").get_caller_identity()["Account"]
    region = os.environ.get("AWS_REGION", "us-east-1")
    base_prefix = f"AWSLogs/{account_id}/BedrockModelInvocationLogs/{region}/{now.strftime('%Y/%m/')}"

    user_tokens = {}
    all_files = set()
    file_count = 0

    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=base_prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith("permission-check"):
                    continue
                file_count += 1
                process_log_file(key, user_tokens)
                all_files.add(key)
    except Exception as e:
        print(f"[full_scan] Error: {e}")

    print(f"[full_scan] Scanned {file_count} files, {len(user_tokens)} users")

    # DynamoDB を上書き（PUT で置き換え）
    for user_arn, tokens in user_tokens.items():
        table.put_item(
            Item={
                "userId": user_arn,
                "currentInputTokens": tokens["input"],
                "currentOutputTokens": tokens["output"],
            })
        total = tokens["input"] + tokens["output"]
        print(
            f"[full_scan] {user_arn}: input={tokens['input']}, output={tokens['output']}, total={total}"
        )

    # 処理済みファイルも更新
    save_processed_files(all_files)
    print(
        f"[full_scan] Done. Updated {len(user_tokens)} users, {len(all_files)} files tracked."
    )


def get_processed_files():
    """DynamoDB から処理済みファイル一覧を取得"""
    try:
        resp = table.get_item(Key={"userId": PROCESSED_KEY})
        item = resp.get("Item", {})
        return set(item.get("files", []))
    except Exception as e:
        print(f"[handler] Error getting processed files: {e}")
        return set()


def save_processed_files(files):
    """DynamoDB に処理済みファイル一覧を保存（直近1000件のみ保持）"""
    recent_files = sorted(files)[-1000:]
    try:
        table.put_item(Item={"userId": PROCESSED_KEY, "files": recent_files})
    except Exception as e:
        print(f"[handler] Error saving processed files: {e}")


def aggregate_from_s3_logs(start_time, processed_files):
    """S3 の Bedrock invocation log から未処理ファイルのみユーザー毎のトークン数を集計"""
    user_tokens = {}
    new_files = set()

    account_id = boto3.client("sts").get_caller_identity()["Account"]
    region = os.environ.get("AWS_REGION", "us-east-1")
    base_prefix = f"AWSLogs/{account_id}/BedrockModelInvocationLogs/{region}/"

    # start_time の日時から対象のプレフィックスを生成（時間単位）
    now = datetime.now(timezone.utc)
    prefixes = set()
    t = start_time
    while t <= now:
        prefixes.add(base_prefix + t.strftime("%Y/%m/%d/%H/"))
        t += timedelta(hours=1)

    file_count = 0
    for full_prefix in sorted(prefixes):
        print(f"[s3] Scanning bucket={BUCKET_NAME}, prefix={full_prefix}")
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=BUCKET_NAME,
                                           Prefix=full_prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key in processed_files:
                        continue
                    if key.endswith("permission-check"):
                        continue
                    file_count += 1
                    process_log_file(key, user_tokens)
                    new_files.add(key)
        except Exception as e:
            print(f"[s3] Error listing S3 objects: {e}")

    print(f"[s3] Processed {file_count} new log files, result: {user_tokens}")
    return user_tokens, new_files


def process_log_file(key, user_tokens):
    """S3 のログファイルを処理。identity.arn からユーザーを特定"""
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=key)
        body = response["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        lines = body.decode("utf-8").strip().split("\n")
        for line in lines:
            if not line:
                continue
            record = json.loads(line)
            user_arn = record.get("identity", {}).get("arn", "")
            if not user_arn:
                print(
                    f"[s3] No identity.arn in record, keys={list(record.keys())}"
                )
                continue
            input_tokens = record.get("input", {}).get("inputTokenCount", 0)
            output_tokens = record.get("output", {}).get("outputTokenCount", 0)
            if input_tokens or output_tokens:
                user_tokens.setdefault(user_arn, {"input": 0, "output": 0})
                user_tokens[user_arn]["input"] += input_tokens
                user_tokens[user_arn]["output"] += output_tokens
                print(
                    f"[s3] user={user_arn}, input={input_tokens}, output={output_tokens}"
                )
    except Exception as e:
        print(f"[s3] Error processing {key}: {e}")


def update_and_check(user_arn, tokens):
    """DynamoDB を更新し、閾値チェック"""
    input_tokens = tokens.get("input", 0)
    output_tokens = tokens.get("output", 0)

    response = table.update_item(
        Key={"userId": user_arn},
        UpdateExpression=
        "ADD currentInputTokens :inp, currentOutputTokens :out",
        ExpressionAttributeValues={
            ":inp": input_tokens,
            ":out": output_tokens,
        },
        ReturnValues="ALL_NEW",
    )
    item = response["Attributes"]
    total_tokens = int(item.get("currentInputTokens", 0)) + int(
        item.get("currentOutputTokens", 0))
    notified = item.get("notified", False)

    # 既に通知済みならスキップ
    if notified:
        return

    # 閾値チェック（トークン数のみ）
    token_exceeded = total_tokens >= TOKEN_LIMIT

    if token_exceeded:
        block_user(user_arn)
        notify(user_arn, total_tokens)
        mark_notified(user_arn)
    elif total_tokens >= TOKEN_LIMIT * 0.8:
        notify_warning(user_arn, total_tokens)
        mark_notified(user_arn)


def mark_notified(user_arn):
    """通知済みフラグを設定"""
    table.update_item(
        Key={"userId": user_arn},
        UpdateExpression="SET notified = :n",
        ExpressionAttributeValues={":n": True},
    )


def block_user(user_arn):
    """IAM User に Deny ポリシーを付与"""
    username = user_arn.split("/")[-1] if "user/" in user_arn else None
    if not username:
        print(f"Cannot extract username from {user_arn}")
        return
    try:
        iam.put_user_policy(
            UserName=username,
            PolicyName=DENY_POLICY_NAME,
            PolicyDocument=DENY_POLICY_DOC,
        )
        table.update_item(
            Key={"userId": user_arn},
            UpdateExpression="SET blocked = :b",
            ExpressionAttributeValues={":b": True},
        )
        print(f"Blocked user: {username}")
    except Exception as e:
        print(f"Error blocking {username}: {e}")


def notify(user_arn, total_tokens):
    """閾値超過通知"""
    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=f"[Bedrock] 利用制限超過: {user_arn.split('/')[-1]}",
        Message=f"ユーザー {user_arn} が月次利用制限を超過しました。\n"
        f"Bedrock へのアクセスをブロックしました。\n\n"
        f"トークン数: {total_tokens:,} / {TOKEN_LIMIT:,}",
    )


def notify_warning(user_arn, total_tokens):
    """80% 警告通知"""
    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=f"[Bedrock] 利用量警告 (80%): {user_arn.split('/')[-1]}",
        Message=f"ユーザー {user_arn} の利用量が80%に達しました。\n"
        f"トークン数: {total_tokens:,} / {TOKEN_LIMIT:,}",
    )


if __name__ == "__main__":
    import sys
    event = {"full_scan": True} if "--full-scan" in sys.argv else {}
    handler(event, None)
