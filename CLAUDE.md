# Claude in Bedrock Usage Control

このプロジェクトは AWS Bedrock の Claude 利用量を制御・監視するための CDK スタックです。

## セッション開始時の必須確認事項

**重要**: 新しい会話セッションを開始したら、必ず以下のファイルを読み込んでプロジェクトのルールとコンテキストを理解してください。

### 参照必須ファイル

1. `.kiro/steering/commit-message.md` - コミットメッセージルール
2. `.kiro/steering/conversion-commits.md` - Conventional Commits 仕様
3. `.kiro/steering/issue-management.md` - Issue 管理ルール

これらのファイルには、開発ワークフロー、コミット規約、Issue 管理方法が詳細に記載されています。
