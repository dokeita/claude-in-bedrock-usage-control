#!/usr/bin/env python3
import aws_cdk as cdk
from bedrock_usage_control.stack import BedrockUsageControlStack

app = cdk.App()
cdk.Tags.of(app).add("DEPLOYED_ENV", "aido")
BedrockUsageControlStack(app, "BedrockUsageControlStack")
app.synth()
