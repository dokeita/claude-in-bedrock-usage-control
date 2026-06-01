from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    aws_s3 as s3,
    aws_logs as logs,
    aws_dynamodb as dynamodb,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_events as events,
    aws_events_targets as targets,
    CustomResource,
    custom_resources as cr,
)
from constructs import Construct


class BedrockUsageControlStack(Stack):
    def __init__(self, scope: Construct, id: str, *, env_prefix: str = "dev", **kwargs):
        super().__init__(scope, id, **kwargs)

        # --- Parameters (context) ---
        alert_email = self.node.try_get_context("alert_email") or ""
        monthly_token_limit = self.node.try_get_context("monthly_token_limit") or 100_000_000
        # monthly_dollar_limit = self.node.try_get_context("monthly_dollar_limit") or 30.0

        # --- S3: Bedrock Invocation Logs ---
        log_bucket = s3.Bucket(
            self, "BedrockLogBucket",
            bucket_name=f"{env_prefix}-bedrock-invocation-logs",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    expiration=Duration.days(365),
                    noncurrent_version_expiration=Duration.days(1),
                ),
            ],
        )
        log_bucket.add_to_resource_policy(iam.PolicyStatement(
            actions=["s3:PutObject"],
            resources=[log_bucket.arn_for_objects("*")],
            principals=[iam.ServicePrincipal("bedrock.amazonaws.com")],
            conditions={"StringEquals": {"aws:SourceAccount": self.account}},
        ))

        # --- CloudWatch Logs ---
        log_group = logs.LogGroup(
            self, "BedrockLogGroup",
            log_group_name=f"/{env_prefix}/aws/bedrock/invocation-logs",
            retention=logs.RetentionDays.THREE_MONTHS,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- DynamoDB: ユーザー毎利用量 ---
        usage_table = dynamodb.Table(
            self, "UsageTable",
            table_name=f"{env_prefix}-bedrock-usage",
            partition_key=dynamodb.Attribute(name="userId", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- SNS: アラート通知 ---
        alert_topic = sns.Topic(self, "AlertTopic", topic_name=f"{env_prefix}-bedrock-usage-alert", display_name=f"{env_prefix} Bedrock Usage Alert")
        if alert_email:
            alert_topic.add_subscription(subs.EmailSubscription(alert_email))

        # --- IAM Role for Bedrock Logging ---
        bedrock_logging_role = iam.Role(
            self, "BedrockLoggingRole",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
        )
        log_bucket.grant_write(bedrock_logging_role)
        log_group.grant_write(bedrock_logging_role)

        # --- Custom Resource Lambda: Bedrock Logging 設定 ---
        configure_logging_fn = lambda_.Function(
            self, "ConfigureLoggingFn",
            function_name=f"{env_prefix}-bedrock-configure-logging",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_asset("lambda/configure_logging"),
            timeout=Duration.seconds(60),
            log_retention=logs.RetentionDays.ONE_MONTH,
        )
        configure_logging_fn.add_to_role_policy(iam.PolicyStatement(
            actions=[
                "bedrock:PutModelInvocationLoggingConfiguration",
                "bedrock:GetModelInvocationLoggingConfiguration",
                "bedrock:DeleteModelInvocationLoggingConfiguration",
            ],
            resources=["*"],
        ))
        configure_logging_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["iam:PassRole"],
            resources=[bedrock_logging_role.role_arn],
        ))

        provider = cr.Provider(self, "LoggingProvider", on_event_handler=configure_logging_fn)
        CustomResource(
            self, "BedrockLoggingConfig",
            service_token=provider.service_token,
            properties={
                "S3BucketName": log_bucket.bucket_name,
                "CloudWatchLogGroupName": log_group.log_group_name,
                "LoggingRoleArn": bedrock_logging_role.role_arn,
            },
        )

        # --- 集計 Lambda ---
        aggregator_fn = lambda_.Function(
            self, "AggregatorFn",
            function_name=f"{env_prefix}-bedrock-aggregator",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_asset("lambda/aggregator"),
            timeout=Duration.minutes(5),
            memory_size=512,
            log_retention=logs.RetentionDays.ONE_MONTH,
            environment={
                "USAGE_TABLE_NAME": usage_table.table_name,
                "LOG_BUCKET_NAME": log_bucket.bucket_name,
                "ALERT_TOPIC_ARN": alert_topic.topic_arn,
                "MONTHLY_TOKEN_LIMIT": str(monthly_token_limit),
                # "MONTHLY_DOLLAR_LIMIT": str(monthly_dollar_limit),
            },
        )
        usage_table.grant_read_write_data(aggregator_fn)
        log_bucket.grant_read(aggregator_fn)
        alert_topic.grant_publish(aggregator_fn)
        aggregator_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["iam:PutUserPolicy", "iam:DeleteUserPolicy"],
            resources=["arn:aws:iam::*:user/*"],
        ))
        aggregator_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["cloudtrail:LookupEvents"],
            resources=["*"],
        ))
        aggregator_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["sts:GetCallerIdentity"],
            resources=["*"],
        ))

        # --- EventBridge Schedule: 15分毎に集計 ---
        events.Rule(
            self, "AggregatorSchedule",
            schedule=events.Schedule.rate(Duration.minutes(15)),
            targets=[targets.LambdaFunction(aggregator_fn)],
        )

        # --- 月初リセット Lambda ---
        reset_fn = lambda_.Function(
            self, "ResetFn",
            function_name=f"{env_prefix}-bedrock-monthly-reset",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_asset("lambda/monthly_reset"),
            timeout=Duration.minutes(2),
            log_retention=logs.RetentionDays.ONE_MONTH,
            environment={
                "USAGE_TABLE_NAME": usage_table.table_name,
            },
        )
        usage_table.grant_read_write_data(reset_fn)
        reset_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["iam:DeleteUserPolicy"],
            resources=["arn:aws:iam::*:user/*"],
        ))

        # --- EventBridge Schedule: 毎月1日 0:00 UTC にリセット ---
        events.Rule(
            self, "MonthlyResetSchedule",
            schedule=events.Schedule.cron(minute="0", hour="0", day="1", month="*"),
            targets=[targets.LambdaFunction(reset_fn)],
        )

        # --- Outputs ---
        CfnOutput(self, "LogBucketName", value=log_bucket.bucket_name)
        CfnOutput(self, "UsageTableName", value=usage_table.table_name)
        CfnOutput(self, "AlertTopicArn", value=alert_topic.topic_arn)
