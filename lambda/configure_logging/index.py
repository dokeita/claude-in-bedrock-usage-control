"""Custom Resource: Bedrock Model Invocation Logging の設定/削除"""
import boto3
import json

bedrock = boto3.client("bedrock")


def handler(event, context):
    request_type = event["RequestType"]
    props = event["ResourceProperties"]

    if request_type in ("Create", "Update"):
        bedrock.put_model_invocation_logging_configuration(
            loggingConfig={
                "cloudWatchConfig": {
                    "logGroupName": props["CloudWatchLogGroupName"],
                    "roleArn": props["LoggingRoleArn"],
                    "largeDataDeliveryS3Config": {
                        "bucketName": props["S3BucketName"],
                    },
                },
                "s3Config": {
                    "bucketName": props["S3BucketName"],
                },
                "textDataDeliveryEnabled": True,
                "imageDataDeliveryEnabled": False,
                "embeddingDataDeliveryEnabled": False,
            }
        )
    elif request_type == "Delete":
        bedrock.delete_model_invocation_logging_configuration()

    return {"PhysicalResourceId": "bedrock-logging-config"}
