# Bedrock Usage Control

Claude Code on Amazon Bedrock を IAM User 認証で利用する際に、ユーザー毎の月次トークン上限を制御する CDK アプリケーション。

## アーキテクチャ

[📐 アーキテクチャ図 (draw.io)](docs/architecture.drawio)

### 処理フロー

1. **ログ収集**: Bedrock Model Invocation Logging が全リクエストを S3 + CloudWatch Logs に記録
2. **集計 (15分毎)**: Aggregator Lambda が S3 の invocation log から `identity.arn` でユーザーを特定し、トークン数を集計（処理済みファイルを追跡して重複カウント防止）
3. **閾値チェック**: DynamoDB の累計値が上限の 80% で警告通知、100% で Bedrock アクセスをブロック（IAM インラインポリシー Deny 付与）。通知は月に1回のみ送信
4. **月初リセット**: 毎月1日に累計値・通知フラグをゼロに戻し、Deny ポリシーを削除

## 前提条件

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
DEPLOYED_ENV=prod npx cdk deploy \
  -c alert_email=admin@example.com \
  -c monthly_token_limit=100000000
```

### 環境変数

| 環境変数 | デフォルト | 説明 |
|----------|-----------|------|
| `DEPLOYED_ENV` | `dev` | リソース名のプレフィックス（例: `prod-bedrock-aggregator`） |

### パラメータ

| パラメータ | デフォルト | 説明 |
|-----------|-----------|------|
| `alert_email` | (なし) | 通知先メールアドレス |
| `monthly_token_limit` | 100,000,000 | 月次トークン上限 (input + output) |

## 運用

### フルスキャン（手動）

当月の S3 ログを全件スキャンして DynamoDB のトークン数を再計算（上書き）する機能。
データの整合性を修正したい場合に使用。

**Lambda コンソールから実行:**
```json
{"full_scan": true}
```

**ローカルから実行:**
```bash
USAGE_TABLE_NAME=<env>-bedrock-usage \
LOG_BUCKET_NAME=<env>-bedrock-invocation-logs \
ALERT_TOPIC_ARN=<topic-arn> \
MONTHLY_TOKEN_LIMIT=100000000 \
AWS_REGION=ap-northeast-1 \
AWS_PROFILE=<profile> \
uv run python lambda/aggregator/index.py --full-scan
```

### スタック削除

`cdk destroy` で全リソース（S3 バケット内オブジェクト含む）が削除されます。

## プロジェクト構成

```
├── app.py                            # CDK エントリポイント
├── cdk.json                          # CDK 設定
├── pyproject.toml                    # uv パッケージ管理
├── bedrock_usage_control/
│   └── stack.py                      # CDK スタック定義
├── lambda/
│   ├── configure_logging/index.py    # Bedrock Logging 設定 (カスタムリソース)
│   ├── aggregator/index.py           # トークン集計 + 閾値制御
│   └── monthly_reset/index.py        # 月初リセット
└── issues/                           # Issue 管理
    ├── pending/                      # 未着手・対応中
    └── closed/                       # 完了
```

## CDK で実現できない設定

| 項目 | 理由 | 対処 |
|------|------|------|
| Bedrock Model Invocation Logging | CloudFormation リソースタイプが存在しない | Lambda カスタムリソースで API 呼び出し（実装済み） |
| Bedrock モデルアクセス有効化 | CloudFormation 非対応 | コンソールから手動で有効化 |

## 制限事項

- 集計は 15 分間隔のため、最大 15 分の遅延でブロックされます（リアルタイム制御ではない）
- DynamoDB テーブルのスキャンを使用しているため、ユーザー数が多い場合はリセット Lambda の実行時間に注意
- S3 invocation log に `identity.arn` が含まれないレコード（`data/` 配下の入力データ）はスキップされます
