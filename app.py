#!/usr/bin/env python3
import os
import aws_cdk as cdk
from bedrock_usage_control.stack import BedrockUsageControlStack

app = cdk.App()
env_prefix = os.environ.get("DEPLOYED_ENV", "dev")
cdk.Tags.of(app).add("DEPLOYED_ENV", env_prefix)
BedrockUsageControlStack(app, f"{env_prefix}-BedrockUsageControlStack", env_prefix=env_prefix)
app.synth()
