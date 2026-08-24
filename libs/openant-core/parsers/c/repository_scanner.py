#!/usr/bin/env python3
"""
Repository Scanner for C/C++ Codebases

Enumerates ALL C/C++ source files in a repository for complete coverage.
This is Phase 1 of the C/C++ parser - file discovery.

Usage:
    python repository_scanner.py <repo_path> [--output <file>] [--exclude <patterns>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "scan_time": "2025-12-30T...",
        "files": [
            { "path": "relative/path/to/file.c", "size": 1234, "extension": ".c" }
        ],
        "statistics": {
            "total_files": 150,
            "total_size_bytes": 500000,
            "directories_scanned": 25,
            "directories_excluded": 10
        }
    }
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from utilities.file_io import read_json, write_json, open_utf8
from core.repo_walk import walk_repository
from core.platforms.openharmony.scope import (
    ROLE_NAMES,
    OpenHarmonyScopeClassifier,
    SOURCE_SCOPES,
)
from utilities.file_io import safe_to_descend


class RepositoryScanner:
    """
    Scan a repository for all C/C++ source files.

    This is Stage 1 of the C/C++ parser pipeline.
    """

    def __init__(self, repo_path: str, options: Optional[Dict] = None):
        self.repo_path = Path(repo_path).resolve()
        options = options or {}

        self.platform = options.get('platform', 'generic')
        if self.platform not in {'auto', 'generic', 'openharmony'}:
            raise ValueError('platform must be one of: auto, generic, openharmony')
        self.skip_tests = options.get('skip_tests', False)
        self.source_scope = None
        self.scope_classifier = None
        self._scope_walk_test_dirs = False
        if self.platform == 'openharmony':
            self.source_scope = options.get('source_scope')
            if self.source_scope is None:
                # ``--no-skip-tests`` is the legacy spelling of the broad
                # research scope. Explicit source_scope remains authoritative.
                self.source_scope = 'production' if self.skip_tests else 'all'
            if self.source_scope not in SOURCE_SCOPES:
                choices = ', '.join(SOURCE_SCOPES)
                raise ValueError(f'source_scope must be one of: {choices}')
            self.scope_classifier = OpenHarmonyScopeClassifier(
                self.repo_path,
                source_scope=self.source_scope,
            )
            # Traverse test/fuzz trees so their omission is counted rather than
            # silently hidden by the legacy directory exclusion list.
            self._scope_walk_test_dirs = 'exclude_patterns' not in options

        self.exclude_patterns: Set[str] = set(options.get('exclude_patterns', [
            '.git',
            '.svn',
            '.hg',
            'node_modules',
            '__pycache__',
            'build',
            'CMakeFiles',
            'third_party',
            'external',
            'vendor',
            'test',
            'tests',
            'testdata',
            'fuzz',
            'doc',
            'docs',
            'demos',
            'examples',
            'man',
            'dist',
            'bin',
            '.cache',
        ]))

        self.source_extensions: Set[str] = set(options.get('source_extensions', [
            '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.hxx', '.hh',
        ]))

        self.test_patterns = {'test/', 'tests/', 'fuzz/', '_test.c', '_test.cpp', 'test_'}

        self.stats = {
            'total_files': 0,
            'total_size_bytes': 0,
            'directories_scanned': 0,
            'directories_excluded': 0,
            'test_files_skipped': 0,
        }

        self.files: List[Dict] = []
        self._reset_scope_state()

    def _reset_scope_state(self) -> None:
        """Reset OpenHarmony-only coverage state before each scan."""
        self._scope_role_counts = {role: 0 for role in ROLE_NAMES}
        self._scope_unsupported_files: List[Dict] = []
        self._scope_metadata_candidates: List[tuple[Path, str]] = []
        self._scope_discovered_files = 0
        self._scope_eligible_files = 0
        self._scope_excluded_directories: Dict[str, int] = {}

    def should_exclude_directory(self, dir_name: str) -> bool:
        """Check if a directory should be excluded."""
        if self._scope_walk_test_dirs and dir_name.lower() in {
            'test', 'tests', 'testdata', 'fuzz', 'fuzztest', 'fuzz_tests',
        }:
            return False
        if dir_name in self.exclude_patterns:
            if self.scope_classifier is not None:
                self._scope_excluded_directories[dir_name] = (
                    self._scope_excluded_directories.get(dir_name, 0) + 1
                )
            return True
        if dir_name.startswith('.') or dir_name.startswith('_'):
            if self.scope_classifier is not None:
                self._scope_excluded_directories[dir_name] = (
                    self._scope_excluded_directories.get(dir_name, 0) + 1
                )
            return True
        if dir_name.startswith('cmake-build-'):
            if self.scope_classifier is not None:
                self._scope_excluded_directories[dir_name] = (
                    self._scope_excluded_directories.get(dir_name, 0) + 1
                )
            return True
        return False

    def is_source_file(self, file_name: str) -> bool:
        """Check if a file is a C/C++ source file."""
        ext = os.path.splitext(file_name)[1].lower()
        return ext in self.source_extensions

    def is_test_file(self, relative_path: str) -> bool:
        """Check if a file is a test file.

        Patterns are matched against path *segments* and filename boundaries,
        not as bare substrings, so ordinary files whose name/path merely
        contains a pattern (e.g. ``latest_value.c`` contains ``test_``;
        ``contest/foo.c`` contains ``test/``) are not misclassified as tests.
        """
        path_lower = relative_path.lower()
        segments = path_lower.split('/')
        basename = segments[-1]
        dir_segments = segments[:-1]
        for pattern in self.test_patterns:
            if pattern.endswith('/'):
                # directory pattern: match a whole path segment (test/, tests/, fuzz/)
                if pattern[:-1] in dir_segments:
                    return True
            elif '.' in pattern:
                # filename-suffix pattern (e.g. _test.c, _test.cpp): compare the stem
                # before the extension, so _test.cc / _test.cxx (common C/C++ test
                # extensions the old substring check also matched) stay detected —
                # without re-introducing substring over-match. Bounded by is_source_file.
                if basename.rsplit('.', 1)[0].endswith(pattern.rsplit('.', 1)[0]):
                    return True
            else:
                # filename-prefix token (test_)
                if basename.startswith(pattern):
                    return True
        return False

    def scan_directory(self, dir_path: Path, relative_path: str = '') -> None:
        """Walk the tree via the shared walker.

        Traversal used to be implemented here, and independently in three sibling
        scanners. Each had to be fixed separately for symlink escape, deep nesting
        and stat-error handling, and each time at least one was missed. The walk now
        lives in ``core/repo_walk.py``; this method keeps only the parts that are
        genuinely language-specific: which files count as source, which count as
        tests, and what a record looks like.
        """
        def _on_file(entry: Path, entry_relative: str) -> None:
            role = None
            if self.scope_classifier is not None:
                role = self.scope_classifier.classify(entry_relative)
                self._scope_role_counts[role] += 1
                self._scope_discovered_files += 1
                if role == 'build_metadata':
                    self._scope_metadata_candidates.append((entry, entry_relative))
                if not self.is_source_file(entry.name):
                    if role == 'unsupported_source' and len(self._scope_unsupported_files) < 100:
                        self._scope_unsupported_files.append({
                            'path': entry_relative,
                            'role': role,
                            'extension': os.path.splitext(entry.name)[1].lower(),
                        })
                    return
                if not self.scope_classifier.accepts(role):
                    skipped = self.stats.setdefault('scope_files_skipped_by_role', {})
                    skipped[role] = skipped.get(role, 0) + 1
                    if role == 'test':
                        self.stats['test_files_skipped'] += 1
                    return
                self._scope_eligible_files += 1
            else:
                if not self.is_source_file(entry.name):
                    return
                if self.skip_tests and self.is_test_file(entry_relative):
                    self.stats['test_files_skipped'] += 1
                    return
            try:
                file_size = entry.stat().st_size
            except OSError:
                file_size = 0
            record = {'path': entry_relative, 'size': file_size}
            record['extension'] = os.path.splitext(entry.name)[1].lower()
            if role is not None:
                record['role'] = role
            self.files.append(record)
            self.stats['total_files'] += 1
            self.stats['total_size_bytes'] += file_size

        walk_repository(
            dir_path,
            should_exclude_directory=self.should_exclude_directory,
            on_file=_on_file,
            stats=self.stats,
        )

    def scan(self) -> Dict:
        """Execute the repository scan and return results."""
        if not self.repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {self.repo_path}")

        if not self.repo_path.is_dir():
            raise NotADirectoryError(f"Repository path is not a directory: {self.repo_path}")

        self.files = []
        self.stats = {
            'total_files': 0,
            'total_size_bytes': 0,
            'directories_scanned': 0,
            'directories_excluded': 0,
            'test_files_skipped': 0,
        }
        self._reset_scope_state()

        self.scan_directory(self.repo_path)

        self.files.sort(key=lambda f: f['path'])

        result = {
            'repository': str(self.repo_path),
            'scan_time': datetime.now().isoformat(),
            'files': self.files,
            'statistics': self.stats,
        }
        if self.scope_classifier is not None:
            result['scope'] = {
                'platform': 'openharmony',
                'source_scope': self.source_scope,
                'coverage': {
                    'discovered_files': self._scope_discovered_files,
                    'eligible_files': self._scope_eligible_files,
                    'parsed_files': len(self.files),
                    'unsupported_files': self._scope_unsupported_files,
                    'parse_failures': [],
                    'roles': self._scope_role_counts,
                    'excluded_directories': self._scope_excluded_directories,
                },
                'build_metadata': self.scope_classifier.collect_build_metadata(
                    self._scope_metadata_candidates,
                ),
            }
        return result


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Scan a C/C++ repository for source files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python repository_scanner.py /path/to/repo
  python repository_scanner.py /path/to/repo --output scan_results.json
  python repository_scanner.py /path/to/repo --skip-tests
        '''
    )

    parser.add_argument('repo_path', help='Path to the repository to scan')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--exclude', help='Comma-separated additional exclude patterns')
    parser.add_argument('--skip-tests', action='store_true', help='Skip test files')

    args = parser.parse_args()

    options = {}
    if args.exclude:
        additional_excludes = [p.strip() for p in args.exclude.split(',')]
        default_excludes = [
            '.git', '.svn', '.hg', 'node_modules', '__pycache__',
            'build', 'CMakeFiles', 'third_party', 'external', 'vendor',
            'test', 'tests', 'testdata', 'fuzz', 'doc', 'docs',
            'demos', 'examples', 'man', 'dist', 'bin', '.cache',
        ]
        options['exclude_patterns'] = default_excludes + additional_excludes

    options['skip_tests'] = args.skip_tests

    try:
        scanner = RepositoryScanner(args.repo_path, options)
        result = scanner.scan()

        output = json.dumps(result, indent=2)

        if args.output:
            with open_utf8(args.output, 'w') as f:
                f.write(output)
            print(f"Scan complete. Results written to: {args.output}", file=sys.stderr)
            print(f"Total files found: {result['statistics']['total_files']}", file=sys.stderr)
            print(f"Total size: {result['statistics']['total_size_bytes']:,} bytes", file=sys.stderr)
            print(f"Directories scanned: {result['statistics']['directories_scanned']}", file=sys.stderr)
            print(f"Directories excluded: {result['statistics']['directories_excluded']}", file=sys.stderr)
            if args.skip_tests:
                print(f"Test files skipped: {result['statistics']['test_files_skipped']}", file=sys.stderr)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
