# Bedrock Usage Control

Claude Code on Amazon Bedrock を IAM User 認証で利用する際に、ユーザー毎の月次トークン/コスト上限を制御する CDK アプリケーション。

## アーキテクチャ

[📐 アーキテクチャ図 (draw.io)](docs/architecture.drawio)

### 処理フロー

1. **ログ収集**: Bedrock Model Invocation Logging が全リクエストを S3 + CloudWatch Logs に記録
2. **集計 (15分毎)**: Aggregator Lambda が CloudTrail から呼び出し元 IAM User を特定し、S3 ログの `requestId` と突き合わせてトークン数を集計
3. **閾値チェック**: DynamoDB の累計値が上限の 80% で警告通知、100% で Bedrock アクセスをブロック（IAM インラインポリシー Deny 付与）
4. **月初リセット**: 毎月1日に累計値をゼロに戻し、Deny ポリシーを削除

## 前提条件

- AWS アカウントで CloudTrail が有効（デフォルトで管理イベントは記録済み）
- Bedrock のモデルアクセスが有効化済み（コンソールから手動設定）
- Node.js (CDK CLI 用)
- [uv](https://docs.astral.sh/uv/) (Python パッケージ管理)

## セットアップ

```bash
# 依存関係インストール
uv sync

# CDK Bootstrap（初回のみ）
npx cdk bootstrap
```

## デプロイ

```bash
npx cdk deploy \
  -c alert_email=admin@example.com \
  -c monthly_token_limit=100000000 \
  -c monthly_dollar_limit=30
```

### パラメータ

| パラメータ | デフォルト | 説明 |
|-----------|-----------|------|
| `alert_email` | (なし) | 通知先メールアドレス |
| `monthly_token_limit` | 100,000,000 | 月次トークン上限 (input + output) |
| `monthly_dollar_limit` | 30.0 | 月次コスト上限 (USD) |

## プロジェクト構成

```
├── app.py                            # CDK エントリポイント
├── cdk.json                          # CDK 設定
├── pyproject.toml                    # uv パッケージ管理
├── bedrock_usage_control/
│   └── stack.py                      # CDK スタック定義
└── lambda/
    ├── configure_logging/index.py    # Bedrock Logging 設定 (カスタムリソース)
    ├── aggregator/index.py           # トークン集計 + 閾値制御
    └── monthly_reset/index.py        # 月初リセット
```

## CDK で実現できない設定

| 項目 | 理由 | 対処 |
|------|------|------|
| Bedrock Model Invocation Logging | CloudFormation リソースタイプが存在しない | Lambda カスタムリソースで API 呼び出し（実装済み） |
| Bedrock モデルアクセス有効化 | CloudFormation 非対応 | コンソールから手動で有効化 |

## コスト計算

集計 Lambda は Claude Sonnet 4 の料金で計算しています（`lambda/aggregator/index.py` の `PRICING` 変数）。
利用モデルが異なる場合は適宜変更してください。

```python
PRICING = {"input": 3.0, "output": 15.0}  # $/1M tokens
```

## 制限事項

- 集計は 15 分間隔のため、最大 15 分の遅延でブロックされます（リアルタイム制御ではない）
- CloudTrail `LookupEvents` は過去 90 日分のイベントのみ参照可能
- DynamoDB テーブルのスキャンを使用しているため、ユーザー数が多い場合はリセット Lambda の実行時間に注意
