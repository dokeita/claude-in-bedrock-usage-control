"""集計 Lambda: CloudTrail から Bedrock 呼び出しユーザーを特定し、
S3 の invocation log からトークン数を集計。閾値超過時に IAM Deny + SNS 通知。"""
import os
import json
import gzip
import boto3
from datetime import datetime, timezone, timedelta
from decimal import Decimal

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
iam = boto3.client("iam")
cloudtrail = boto3.client("cloudtrail")

TABLE_NAME = os.environ["USAGE_TABLE_NAME"]
BUCKET_NAME = os.environ["LOG_BUCKET_NAME"]
TOPIC_ARN = os.environ["ALERT_TOPIC_ARN"]
TOKEN_LIMIT = int(os.environ["MONTHLY_TOKEN_LIMIT"])
# DOLLAR_LIMIT = float(os.environ["MONTHLY_DOLLAR_LIMIT"])

# # Claude Sonnet 4 pricing ($/1M tokens) - 必要に応じて変更
# PRICING = {"input": 3.0, "output": 15.0}

DENY_POLICY_NAME = "BedrockUsageLimitDeny"
DENY_POLICY_DOC = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": ["bedrock:InvokeModel*", "bedrock:Converse*"],
        "Resource": "*",
    }]
})

table = dynamodb.Table(TABLE_NAME)


def handler(event, context):
    now = datetime.now(timezone.utc)
    # 過去 15 分のログを処理
    start_time = now - timedelta(minutes=16)

    # CloudTrail から Bedrock InvokeModel/Converse イベントを取得
    user_tokens = aggregate_from_cloudtrail(start_time, now)

    # DynamoDB 更新 + 閾値チェック
    for user_id, tokens in user_tokens.items():
        update_and_check(user_id, tokens)


def aggregate_from_cloudtrail(start_time, end_time):
    """CloudTrail から Bedrock 呼び出しイベントを取得し、ユーザー毎のトークン数を集計"""
    user_tokens = {}  # {user_arn: {"input": N, "output": N}}

    paginator = cloudtrail.get_paginator("lookup_events")
    for event_name in ["InvokeModel", "Converse", "ConverseStream", "InvokeModelWithResponseStream"]:
        pages = paginator.paginate(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
            StartTime=start_time,
            EndTime=end_time,
        )
        for page in pages:
            for ct_event in page.get("Events", []):
                detail = json.loads(ct_event.get("CloudTrailEvent", "{}"))
                user_arn = detail.get("userIdentity", {}).get("arn", "")
                if not user_arn:
                    continue
                # requestId で S3 ログと突き合わせ可能だが、
                # CloudTrail の responseElements にトークン情報がない場合は
                # S3 ログから取得する必要がある
                request_id = detail.get("requestID", "")
                if request_id:
                    user_tokens.setdefault(user_arn, []).append(request_id)

    # S3 ログからトークン数を取得
    return aggregate_tokens_from_s3(user_tokens, start_time)


def aggregate_tokens_from_s3(user_request_ids, start_time):
    """S3 の invocation log から request_id ベースでトークン数を集計"""
    # request_id → user_arn のマッピング
    request_to_user = {}
    for user_arn, req_ids in user_request_ids.items():
        for rid in req_ids:
            request_to_user[rid] = user_arn

    if not request_to_user:
        return {}

    user_tokens = {}  # {user_arn: {"input": N, "output": N}}

    # S3 のログプレフィックスを構築 (Bedrock のログパス形式)
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    prefix = f"AWSLogs/{account_id}/BedrockModelInvocationLogs/"
    # 日付ベースでプレフィックスを絞る
    date_prefix = start_time.strftime("%Y/%m/%d/")

    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=prefix + date_prefix):
            for obj in page.get("Contents", []):
                process_log_file(obj["Key"], request_to_user, user_tokens)
    except Exception as e:
        print(f"Error listing S3 objects: {e}")

    return user_tokens


def process_log_file(key, request_to_user, user_tokens):
    """S3 のログファイル (gzip JSON) を処理"""
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=key)
        body = response["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        # ログファイルは JSONL 形式の場合がある
        for line in body.decode("utf-8").strip().split("\n"):
            if not line:
                continue
            record = json.loads(line)
            request_id = record.get("requestId", "")
            if request_id in request_to_user:
                user_arn = request_to_user[request_id]
                input_tokens = record.get("input", {}).get("inputTokenCount", 0)
                output_tokens = record.get("output", {}).get("outputTokenCount", 0)
                user_tokens.setdefault(user_arn, {"input": 0, "output": 0})
                user_tokens[user_arn]["input"] += input_tokens
                user_tokens[user_arn]["output"] += output_tokens
    except Exception as e:
        print(f"Error processing {key}: {e}")


def update_and_check(user_arn, tokens):
    """DynamoDB を更新し、閾値チェック"""
    input_tokens = tokens.get("input", 0)
    output_tokens = tokens.get("output", 0)
    # cost = (input_tokens * PRICING["input"] + output_tokens * PRICING["output"]) / 1_000_000

    response = table.update_item(
        Key={"userId": user_arn},
        UpdateExpression="ADD currentInputTokens :inp, currentOutputTokens :out",
        ExpressionAttributeValues={
            ":inp": input_tokens,
            ":out": output_tokens,
            # ":cost": Decimal(str(round(cost, 6))),
        },
        ReturnValues="ALL_NEW",
    )
    item = response["Attributes"]
    total_tokens = int(item.get("currentInputTokens", 0)) + int(item.get("currentOutputTokens", 0))
    # total_cost = float(item.get("currentCostDollars", 0))

    # 閾値チェック（トークン数のみ）
    token_exceeded = total_tokens >= TOKEN_LIMIT
    # cost_exceeded = total_cost >= DOLLAR_LIMIT

    if token_exceeded:
        block_user(user_arn)
        notify(user_arn, total_tokens, token_exceeded=True)
    elif total_tokens >= TOKEN_LIMIT * 0.8:
        notify_warning(user_arn, total_tokens)


def block_user(user_arn):
    """IAM User に Deny ポリシーを付与"""
    # ARN から username を抽出: arn:aws:iam::123456789012:user/alice
    username = user_arn.split("/")[-1] if "/user/" in user_arn else None
    if not username:
        print(f"Cannot extract username from {user_arn}")
        return
    try:
        iam.put_user_policy(
            UserName=username,
            PolicyName=DENY_POLICY_NAME,
            PolicyDocument=DENY_POLICY_DOC,
        )
        # DynamoDB に blocked フラグを設定
        table.update_item(
            Key={"userId": user_arn},
            UpdateExpression="SET blocked = :b",
            ExpressionAttributeValues={":b": True},
        )
        print(f"Blocked user: {username}")
    except Exception as e:
        print(f"Error blocking {username}: {e}")


def notify(user_arn, total_tokens, token_exceeded):
    """閾値超過通知"""
    reason = []
    if token_exceeded:
        reason.append(f"トークン数: {total_tokens:,} / {TOKEN_LIMIT:,}")
    # if cost_exceeded:
    #     reason.append(f"コスト: ${total_cost:.2f} / ${DOLLAR_LIMIT:.2f}")

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=f"[Bedrock] 利用制限超過: {user_arn.split('/')[-1]}",
        Message=f"ユーザー {user_arn} が月次利用制限を超過しました。\n"
                f"Bedrock へのアクセスをブロックしました。\n\n"
                + "\n".join(reason),
    )


def notify_warning(user_arn, total_tokens):
    """80% 警告通知"""
    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=f"[Bedrock] 利用量警告 (80%): {user_arn.split('/')[-1]}",
        Message=f"ユーザー {user_arn} の利用量が80%に達しました。\n"
                f"トークン数: {total_tokens:,} / {TOKEN_LIMIT:,}",
    )
