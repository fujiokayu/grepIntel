"""
Pattern management module for GrepIntel.

This module provides functionality to load and manage security patterns
for different programming languages and frameworks.
"""

import os
import re
from typing import Dict, List, Any, Optional


class PatternManager:
    """
    Manages security patterns for different programming languages and frameworks.

    Attributes:
        language_patterns (Dict): Dictionary of patterns organized by language and security aspect.
        framework_patterns (Dict): Dictionary of patterns organized by framework and security aspect.
        combined_patterns (Dict): Dictionary of combined patterns from both language and framework.
        patterns (Dict): Dictionary of patterns (maintained for backward compatibility).
    """

    def __init__(self):
        """Initialize a new PatternManager instance."""
        # 言語ごとのパターン
        self.language_patterns: Dict[str, Dict[str, Dict[str, Any]]] = {}
        # フレームワークごとのパターン
        self.framework_patterns: Dict[str, Dict[str, Dict[str, Any]]] = {}
        # 結合されたパターン（実際の検索に使用）
        self.combined_patterns: Dict[str, Dict[str, Dict[str, Any]]] = {}
        # 後方互換性のために維持
        self.patterns: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def _load_patterns_from_file(
        self, file_path: str, target_dict: Dict, key: str
    ) -> None:
        """
        内部メソッド: ファイルからパターンをロードして指定された辞書に格納する

        Args:
            file_path (str): パターンファイルのパス
            target_dict (Dict): パターンを格納する辞書
            key (str): 辞書のキー（言語またはフレームワーク名）

        Raises:
            FileNotFoundError: パターンファイルが存在しない場合
            ValueError: パターンファイルの形式が無効な場合
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Pattern file not found: {file_path}")

        # 指定されたキーの辞書を初期化（存在しない場合）
        if key not in target_dict:
            target_dict[key] = {}

        # パターンファイルを読み込む
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        # パターンファイルを解析
        current_section = None
        current_description = None
        current_patterns = []

        for line in content.splitlines():
            line = line.strip()

            # 空行をスキップ
            if not line:
                continue

            # セクションヘッダーをチェック
            section_match = re.match(r"^\[(.*)\]$", line)
            if section_match:
                # 前のセクションが存在する場合は保存
                if current_section:
                    target_dict[key][current_section] = {
                        "description": current_description,
                        "patterns": current_patterns,
                    }

                # 新しいセクションを開始
                current_section = section_match.group(1)
                current_description = None
                current_patterns = []
                continue

            # 説明をチェック
            if line.startswith("description:"):
                current_description = line[len("description:") :].strip()
                continue

            # パターンリストをチェック
            if line == "patterns:":
                continue

            # パターン項目をチェック
            if line.startswith("- "):
                pattern = line[2:].strip()
                current_patterns.append(pattern)
                continue

        # 最後のセクションを保存
        if current_section:
            target_dict[key][current_section] = {
                "description": current_description,
                "patterns": current_patterns,
            }

    def load_language_patterns(self, file_path: str, language: str) -> None:
        """
        言語固有のセキュリティパターンをファイルからロードする

        Args:
            file_path (str): パターンファイルのパス
            language (str): プログラミング言語識別子（例: 'php', 'java'）

        Raises:
            FileNotFoundError: パターンファイルが存在しない場合
            ValueError: パターンファイルの形式が無効な場合
        """
        self._load_patterns_from_file(file_path, self.language_patterns, language)
        # 後方互換性のために patterns も更新
        self._load_patterns_from_file(file_path, self.patterns, language)
        # 結合パターンを更新
        self._update_combined_patterns(language)

    def load_framework_patterns(
        self, file_path: str, framework: str, language: str
    ) -> None:
        """
        フレームワーク固有のセキュリティパターンをファイルからロードする

        Args:
            file_path (str): パターンファイルのパス
            framework (str): フレームワーク識別子（例: 'laravel', 'rails'）
            language (str): 関連するプログラミング言語

        Raises:
            FileNotFoundError: パターンファイルが存在しない場合
            ValueError: パターンファイルの形式が無効な場合
        """
        self._load_patterns_from_file(file_path, self.framework_patterns, framework)
        # 結合パターンを更新
        self._update_combined_patterns(language)

    def _update_combined_patterns(self, language: str) -> None:
        """
        言語とフレームワークのパターンを結合する

        Args:
            language (str): 結合するパターンの言語
        """
        if language not in self.combined_patterns:
            self.combined_patterns[language] = {}

        # 言語パターンをコピー
        if language in self.language_patterns:
            for vuln_type, data in self.language_patterns[language].items():
                if vuln_type not in self.combined_patterns[language]:
                    self.combined_patterns[language][vuln_type] = {
                        "description": data["description"],
                        "patterns": data["patterns"].copy(),
                    }
                else:
                    # 既存のパターンリストを更新
                    self.combined_patterns[language][vuln_type]["patterns"] = data[
                        "patterns"
                    ].copy()

        # フレームワークパターンを追加
        for framework, framework_data in self.framework_patterns.items():
            for vuln_type, data in framework_data.items():
                # 既存の脆弱性タイプならパターンを追加
                if vuln_type in self.combined_patterns[language]:
                    # 重複を避けるために既存のパターンをチェック
                    existing_patterns = set(
                        self.combined_patterns[language][vuln_type]["patterns"]
                    )
                    for pattern in data["patterns"]:
                        if pattern not in existing_patterns:
                            self.combined_patterns[language][vuln_type][
                                "patterns"
                            ].append(pattern)
                # 新しい脆弱性タイプなら新規追加
                else:
                    self.combined_patterns[language][vuln_type] = {
                        "description": data["description"],
                        "patterns": data["patterns"].copy(),
                    }

    def load_patterns_from_file(self, file_path: str, language: str) -> None:
        """
        セキュリティパターンをファイルからロードする（後方互換性のため）

        Args:
            file_path (str): パターンファイルのパス
            language (str): プログラミング言語識別子（例: 'php', 'java'）

        Raises:
            FileNotFoundError: パターンファイルが存在しない場合
            ValueError: パターンファイルの形式が無効な場合
        """
        self.load_language_patterns(file_path, language)

    def load_patterns_from_directory(
        self, directory_path: str, is_framework: bool = False
    ) -> None:
        """
        ディレクトリからすべてのパターンファイルをロードする

        Args:
            directory_path (str): パターンファイルを含むディレクトリのパス
            is_framework (bool): フレームワークパターンとしてロードするかどうか

        Raises:
            FileNotFoundError: ディレクトリが存在しない場合
        """
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Pattern directory not found: {directory_path}")

        for filename in os.listdir(directory_path):
            if filename.endswith(".txt"):
                name = os.path.splitext(filename)[0]
                file_path = os.path.join(directory_path, filename)

                if is_framework:
                    # フレームワークパターンの場合、関連する言語を特定する必要がある
                    # 実際の実装では、フレームワークと言語のマッピングを使用する
                    from src.config import FRAMEWORK_LANGUAGE_MAP

                    if name in FRAMEWORK_LANGUAGE_MAP:
                        language = FRAMEWORK_LANGUAGE_MAP[name]
                        self.load_framework_patterns(file_path, name, language)
                else:
                    # 言語パターンの場合
                    self.load_language_patterns(file_path, name)

    def get_patterns_for_language(self, language: str) -> Dict[str, Dict[str, Any]]:
        """
        特定の言語のすべてのパターンを取得する

        Args:
            language (str): プログラミング言語識別子（例: 'php', 'java'）

        Returns:
            Dict: 指定された言語のパターン辞書

        Raises:
            ValueError: 言語がサポートされていない場合
        """
        # 結合パターンを優先
        if language in self.combined_patterns:
            return self.combined_patterns[language]

        # 後方互換性のため
        if language not in self.patterns:
            raise ValueError(f"Unsupported language: {language}")

        return self.patterns[language]

    def get_all_patterns(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        すべての言語のすべてのパターンを取得する

        Returns:
            Dict: 言語とセキュリティの側面によって整理されたすべてのパターンの辞書
        """
        # 結合パターンを優先
        if self.combined_patterns:
            return self.combined_patterns

        # 後方互換性のため
        return self.patterns
