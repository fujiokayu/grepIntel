# セキュリティ評価レポート

## 概要
- **対象:** {target}
- **スキャン日時:** {scan_date}
- **分析言語:** {languages}
- **スキャンファイル数:** {files_scanned}
- **検出された脆弱性:** {total_vulnerabilities}

## エグゼクティブサマリー
{summary}

## 脆弱性の発見

{for each vulnerability}
### {vulnerability_id}: {vulnerability_title}
**重要度:** {severity}  
**場所:** {file_path}:{line_number}  
**タイプ:** {vulnerability_type}  
**マッチしたパターン:** `{pattern}`

#### コードスニペット
```{language}
{code_snippet}
```

#### 分析
{llm_analysis}

#### 推奨対策
{recommendation}

---
{end for}

## 統計
- **高重要度の問題:** {high_severity_count}
- **中重要度の問題:** {medium_severity_count}
- **低重要度の問題:** {low_severity_count}
- **誤検出:** {false_positive_count}

## 方法論
このセキュリティ評価は、GrepIntelを使用して実施されました。GrepIntelは、パターンベースの識別とLLM駆動の分析を組み合わせて、ソースコード内の潜在的なセキュリティ脆弱性を検出するツールです。プロセスには以下が含まれます：

1. パターンマッチングによる潜在的に脆弱なコードセクションの特定
2. マッチしたパターン周辺のコンテキスト抽出
3. 特定されたコードが本物のセキュリティ脆弱性を表しているかどうかを判断するためのLLMベースの分析
4. 潜在的な影響と悪用可能性に基づく重要度評価
5. 修復のための推奨事項の生成

## 免責事項
このレポートは自動的に生成されたものであり、セキュリティの専門家によるレビューが必要です。このツールは高度な技術を使用して脆弱性を特定しますが、すべてのセキュリティ問題を検出できるわけではなく、一部の発見は誤検出である可能性があります。
