import os
import textwrap
from pathlib import Path

import pytest

from detect_secrets.core import scan
from detect_secrets.settings import transient_settings
from detect_secrets.util import git
from detect_secrets.util.path import get_relative_path_if_in_cwd
from testing.mocks import mock_named_temporary_file


class TestGetFilesToScan:
    @staticmethod
    def test_should_scan_specific_non_tracked_file(non_tracked_file):
        assert list(scan.get_files_to_scan(non_tracked_file.name, should_scan_all_files=False))

    @staticmethod
    def test_should_scan_tracked_files_in_directory(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) not in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=False,
                ),
            )
        )

    @staticmethod
    def test_should_scan_all_files_in_directory_if_flag_is_provided(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=True,
                ),
            )
        )

    @staticmethod
    def test_handles_each_path_separately(non_tracked_file):
        results = list(
            scan.get_files_to_scan(
                non_tracked_file.name,
                'test_data/short_files',
            ),
        )

        # This implies that the test_data/short_files directory is scanned, because otherwise,
        # it would only be one file. However, at the same time, this test case isn't fragile to
        # additions to this directory.
        assert len(results) > 2

    @staticmethod
    def test_handles_multiple_directories():
        directories = [Path('test_data/short_files'), Path('test_data/files')]
        results = list(scan.get_files_to_scan(*directories))

        for prefix in directories:
            assert len(list(filter(lambda x: x.startswith(str(prefix)), results))) > 1

    @staticmethod
    @pytest.fixture(autouse=True, scope='class')
    def non_tracked_file():
        with mock_named_temporary_file(
            prefix=os.path.join(git.get_root_directory(), 'test_data/'),
        ) as f:
            f.write(b'content does not matter')
            f.seek(0)

            yield f


class TestScanFile:
    # High-entropy values that exceed the Base64HighEntropyString default limit (4.5),
    # so they are detected regardless of whether they are quoted.
    QUOTED_SECRET = 'gX69YO4CvBsVjzAwYxdGyDd30t5+9ez31gKATtj4'
    UNQUOTED_SECRET = 'hA70ZP5DwCtWk0BxYxHzEe41u6+0fa42hLBUuk5'

    @staticmethod
    def test_handles_broken_yaml_gracefully():
        with mock_named_temporary_file(suffix='.yaml') as f:
            f.write(
                textwrap.dedent("""
                metadata:
                    name: {{ .values.name }}
                """)[1:].encode(),
            )
            f.seek(0)

            assert not list(scan.scan_file(f.name))

    @staticmethod
    def test_handles_binary_files_gracefully():
        # NOTE: This suffix needs to be something that isn't in the known file types, as determined
        # by `detect_secrets.util.filetype.determine_file_type`.
        with mock_named_temporary_file(suffix='.woff2') as f:
            f.write(b'\x86')
            f.seek(0)

            assert not list(scan.scan_file(f.name))

    @staticmethod
    @pytest.mark.parametrize(
        'content, expected_secrets, expected_line_numbers',
        (
            # Quoted and unquoted secrets coexisting: both must survive, even though the lazy
            # pass matches the quoted one first (which used to short-circuit the eager pass).
            (
                'quoted="{quoted}"\nunquoted={unquoted}\n',
                {'{quoted}', '{unquoted}'},
                {1, 2},
            ),

            # Reversing the order must not change the result set: the old failure was a
            # file-level short-circuit, not an ordering effect.
            (
                'unquoted={unquoted}\nquoted="{quoted}"\n',
                {'{quoted}', '{unquoted}'},
                {1, 2},
            ),

            # Pure quoted file: the lazy pass alone is sufficient.
            (
                'quoted="{quoted}"\n',
                {'{quoted}'},
                {1},
            ),

            # Pure unquoted file: only the eager pass can add the quotes the plugin requires.
            (
                'unquoted={unquoted}\n',
                {'{unquoted}'},
                {1},
            ),
        ),
    )
    def test_quoted_and_unquoted_secrets_in_env_file(
        content,
        expected_secrets,
        expected_line_numbers,
    ):
        content = content.format(
            quoted=TestScanFile.QUOTED_SECRET,
            unquoted=TestScanFile.UNQUOTED_SECRET,
        )
        expected_secrets = {
            value.format(
                quoted=TestScanFile.QUOTED_SECRET,
                unquoted=TestScanFile.UNQUOTED_SECRET,
            )
            for value in expected_secrets
        }

        with transient_settings({
            'plugins_used': [
                {
                    'name': 'Base64HighEntropyString',
                },
            ],
        }):
            with mock_named_temporary_file(suffix='.env') as f:
                f.write(content.encode())
                f.seek(0)

                secrets = list(scan.scan_file(f.name))

        assert {secret.secret_value for secret in secrets} == expected_secrets
        assert {secret.line_number for secret in secrets} == expected_line_numbers
        # Identity-based deduplication (filename, hash, type) must keep the two-pass output
        # free of duplicates.
        assert len(secrets) == len(expected_secrets)


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [
            {
                'name': 'BasicAuthDetector',
            },
        ],
    }):
        yield
