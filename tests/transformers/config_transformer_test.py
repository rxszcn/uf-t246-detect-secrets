import configparser
import textwrap

import pytest

from detect_secrets.transformers.config import ConfigFileTransformer
from detect_secrets.transformers.config import EagerConfigFileTransformer
from detect_secrets.transformers.config import IniFileParser
from detect_secrets.util.filetype import FileType
from testing.mocks import mock_file_object


@pytest.mark.parametrize(
    'transformer',
    (
        ConfigFileTransformer,
        EagerConfigFileTransformer,
    ),
)
def test_transformer(transformer):
    file = mock_file_object(
        textwrap.dedent("""
            [section]
            keyA = value

            keyB = "double"
            keyC = 'single'

            keyD = o'brian
            keyE = "chai" tea
        """)[1:-1],
    )

    assert transformer().parse_file(file) == [
        '',
        'keyA = "value"',
        '',
        'keyB = "double"',
        'keyC = "single"',
        '',
        'keyD = "o\'brian"',
        'keyE = "\\\"chai\\\" tea"',
    ]


@pytest.mark.parametrize(
    'transformer',
    (
        ConfigFileTransformer,
        EagerConfigFileTransformer,
    ),
)
def test_transformer_persist_pragma_comments(transformer):
    file = mock_file_object(
        textwrap.dedent("""
            [section]
            keyA = value

            # pragma: allowlist nextline secret
            keyB = "double"
            keyC = 'single'

            # pragma: allowlist nextline secret
            keyD = o'brian
            keyE = "chai" tea
        """)[1:-1],
    )

    assert transformer().parse_file(file) == [
        '',
        'keyA = "value"',
        '',
        '# pragma: allowlist nextline secret',
        'keyB = "double"',
        'keyC = "single"',
        '',
        '# pragma: allowlist nextline secret',
        'keyD = "o\'brian"',
        'keyE = "\\\"chai\\\" tea"',
    ]


def test_basic():
    file = mock_file_object(
        textwrap.dedent("""
            [section]
            key = value
            rice = fried

            # comment
            tea = chai

            [other]

            water = unflavored
        """)[1:-1],
    )

    assert list(IniFileParser(file)) == [
        ('key', 'value', 2),
        ('rice', 'fried', 3),
        ('tea', 'chai', 6),
        ('water', 'unflavored', 10),
    ]


def test_basic_persist_pragma_comments_pound():
    file = mock_file_object(
        textwrap.dedent("""
            [section]
            # pragma: allowlist nextline secret
            key = value
            # pragma: allowlist nextline secret
            rice = fried

            # comment
            tea = chai

            [other]
            # pragma: allowlist nextline secret
            water = unflavored
        """)[1:-1],
    )

    assert list(IniFileParser(file)) == [
        ('key', '# pragma: allowlist nextline secret', 2),
        ('key', 'value', 3),
        ('key', '# pragma: allowlist nextline secret', 4),
        ('rice', 'fried', 5),
        ('tea', 'chai', 8),
        ('water', '# pragma: allowlist nextline secret', 11),
        ('water', 'unflavored', 12),
    ]


def test_basic_persist_pragma_comments_semi_colon():
    file = mock_file_object(
        textwrap.dedent("""
            [section]
            ; pragma: allowlist nextline secret
            key = value
            ; pragma: allowlist nextline secret
            rice = fried

            ; comment
            tea = chai

            [other]
            ; pragma: allowlist nextline secret
            water = unflavored
        """)[1:-1],
    )

    assert list(IniFileParser(file)) == [
        ('key', '; pragma: allowlist nextline secret', 2),
        ('key', 'value', 3),
        ('key', '; pragma: allowlist nextline secret', 4),
        ('rice', 'fried', 5),
        ('tea', 'chai', 8),
        ('water', '; pragma: allowlist nextline secret', 11),
        ('water', 'unflavored', 12),
    ]


@pytest.mark.parametrize(
    'content',
    (
        textwrap.dedent("""
            key = value

            # comment
            tea = chai
        """)[1:-1],

        # This case needs `add_header=True` to work.
        textwrap.dedent("""
            key = value

            [other]
            water = unflavored
        """)[1:-1],
    ),
)
def test_not_ini_file(content):
    file = mock_file_object(content)

    with pytest.raises(configparser.Error):
        list(IniFileParser(file))


def test_add_header():
    file = mock_file_object(
        textwrap.dedent("""
            key = value

            # comment
            tea = chai
        """)[1:-1],
    )

    assert list(IniFileParser(file, add_header=True)) == [
        ('key', 'value', 1),
        ('tea', 'chai', 4),
    ]


class TestMultipleValues:
    @staticmethod
    def test_all():
        file = mock_file_object(
            textwrap.dedent("""
                [section]
                key = value0
                    value1

                    # comment
                    value2
            """)[1:-1],
        )

        assert list(IniFileParser(file)) == [
            ('key', 'value0', 2),
            ('key', 'value1', 3),
            ('key', 'value2', 6),
        ]

    @staticmethod
    def test_not_first():
        file = mock_file_object(
            textwrap.dedent("""
                [section]
                key =
                    value1

                    # comment
                    value2
            """)[1:-1],
        )

        assert list(IniFileParser(file)) == [
            ('key', 'value1', 3),
            ('key', 'value2', 6),
        ]

    @staticmethod
    def test_pragma_comments():
        file = mock_file_object(
            textwrap.dedent("""
                [section]
                # pragma: allowlist nextline secret
                key = value0
                    # pragma: allowlist nextline secret
                    value1

                    # comment
                    value2
            """)[1:-1],
        )

        assert list(IniFileParser(file)) == [
            ('key', '# pragma: allowlist nextline secret', 2),
            ('key', 'value0', 3),
            ('key', '# pragma: allowlist nextline secret', 4),
            ('key', 'value1', 5),
            ('key', 'value2', 8),
        ]


def test_eager_transformer_only_applies_to_other_file_types():
    # The non-eager transformer unconditionally claims config-looking files; the eager
    # variant is restricted to `FileType.OTHER` (e.g. `.env`). This split is what makes the
    # scanner's two-pass contract work: unquoted values only get their artificial quotes on
    # the eager fallback pass, so relaxing this restriction would change which pass finds
    # what and re-introduce the file-level short-circuit.
    assert ConfigFileTransformer().is_eager is False
    assert EagerConfigFileTransformer().is_eager is True

    eager_transformer = EagerConfigFileTransformer()

    assert FileType.OTHER.value != FileType.INI.value
    assert eager_transformer.should_parse_file('config.env') is True
    assert eager_transformer.should_parse_file('config.ini') is False


def test_eager_transformer_adds_quotes_to_unquoted_env_values():
    # `.env` files have no section header, so the eager transformer prepends one and
    # normalizes every value into an artificially-quoted assignment. The high-entropy plugin
    # only matches quoted strings, which is why unquoted secrets depend on this pass.
    file = mock_file_object(
        textwrap.dedent("""
            quoted="gX69YO4CvBsVjzAwYxdGyDd30t5+9ez31gKATtj4"
            unquoted=hA70ZP5DwCtWk0BxYxHzEe41u6+0fa42hLBUuk5
        """)[1:-1],
    )

    assert EagerConfigFileTransformer().parse_file(file) == [
        'quoted = "gX69YO4CvBsVjzAwYxdGyDd30t5+9ez31gKATtj4"',
        'unquoted = "hA70ZP5DwCtWk0BxYxHzEe41u6+0fa42hLBUuk5"',
    ]
