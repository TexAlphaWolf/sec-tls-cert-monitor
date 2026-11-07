import pytest

from tlswatch.config import ConfigError, load, parse_target
from tlswatch.model import Target


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("example.org", Target("example.org", 443)),
        ("example.org:8443", Target("example.org", 8443)),
        ("https://example.org", Target("example.org", 443)),
        ("tls://example.org:993/", Target("example.org", 993)),
        ("[2001:db8::1]:8443", Target("2001:db8::1", 8443)),
        ("[2001:db8::1]", Target("2001:db8::1", 443)),
        ("2001:db8::1", Target("2001:db8::1", 443)),
        ("smtp://mail.example.org", Target("mail.example.org", 25, starttls="smtp")),
        ("smtp://mail.example.org:587", Target("mail.example.org", 587, starttls="smtp")),
        ("imap://mail.example.org", Target("mail.example.org", 143, starttls="imap")),
        ("pop3://mail.example.org", Target("mail.example.org", 110, starttls="pop3")),
        (" example.org ", Target("example.org", 443)),
    ],
)
def test_targets(text, expected):
    assert parse_target(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        "example.org:0",
        "example.org:99999",
        "example.org:http",
        "ftp://example.org",
        "a b",
        "user@example.org",
        "[::1",
        "[::1]x",
        "example.org/path",
    ],
)
def test_bad_targets(text):
    with pytest.raises(ConfigError):
        parse_target(text)


def test_options_given_with_a_target():
    target = parse_target("host:25", starttls="smtp", server_name="mail.example", ca_file="ca.pem")
    assert (target.starttls, target.server_name, target.ca_file) == (
        "smtp",
        "mail.example",
        "ca.pem",
    )
    assert target.name == "mail.example" and Target("h").name == "h"
    assert parse_target("host", starttls="imap").port == 143
    with pytest.raises(ConfigError):
        parse_target("host", starttls="gopher")


def test_the_label_brackets_ipv6():
    assert Target("::1", 443).label == "[::1]:443" and Target("a.b", 25).label == "a.b:25"


def write(tmp_path, text):
    path = tmp_path / "tlswatch.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_a_full_config_file(tmp_path):
    path = write(
        tmp_path,
        """
[settings]
timeout = 3
warn_days = 21
critical_days = 5
workers = 4
min_grade = "C"

[[hosts]]
host = "example.org"

[[hosts]]
host = "mail.example.org"
port = 587
starttls = "smtp"
server_name = "mx.example.org"
ca_file = "private-ca.pem"
""",
    )
    settings = load(path)
    assert (
        settings.timeout,
        settings.warn_days,
        settings.critical_days,
        settings.workers,
        settings.min_grade,
    ) == (3, 21, 5, 4, "C")
    first, second = settings.targets
    assert first == Target("example.org", 443)
    assert (second.port, second.starttls, second.server_name) == (587, "smtp", "mx.example.org")
    assert second.ca_file == str((tmp_path / "private-ca.pem").resolve())  # relative to the file


def test_an_empty_file_is_valid(tmp_path):
    settings = load(write(tmp_path, ""))
    assert settings.targets == [] and settings.timeout is None


@pytest.mark.parametrize(
    "text",
    [
        "[settings]\nspeed = 1\n",
        '[settings]\nmin_grade = "E"\n',
        "[settings]\ntimeout = 0\n",
        '[settings]\nwarn_days = "soon"\n',
        "[settings]\nworkers = true\n",
        "[colours]\nx = 1\n",
        "[[hosts]]\nport = 443\n",
        '[[hosts]]\nhost = "a"\nspeed = 1\n',
        '[[hosts]]\nhost = "a"\nport = "443"\n',
        '[[hosts]]\nhost = "a"\nstarttls = "gopher"\n',
        "hosts = 3\n",
        "this is = not toml [\n",
    ],
)
def test_bad_files_are_explained(tmp_path, text):
    with pytest.raises(ConfigError):
        load(write(tmp_path, text))


def test_a_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load(tmp_path / "nope.toml")
