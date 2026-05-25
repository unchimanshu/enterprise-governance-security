from unittest.mock import MagicMock, patch, call

from main import (
    build_summary,
    extract_changed_python_files,
    fetch_pr_diff,
    write_changed_files_locally,
)


# --- build_summary ---

def test_build_summary_zero_violations():
    assert build_summary(0) == "No HIPAA violations detected."


def test_build_summary_one_violation():
    summary = build_summary(1)
    assert "1" in summary
    assert "blocked" in summary.lower()


def test_build_summary_multiple_violations():
    summary = build_summary(5)
    assert "5" in summary


# --- fetch_pr_diff ---

def test_fetch_pr_diff_returns_diff_text():
    with patch("main.requests.get") as mock_get:
        mock_response = MagicMock(text="--- a/file.py\n+++ b/file.py")
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        diff = fetch_pr_diff("org/repo", 42, "gh-token")

    assert diff == "--- a/file.py\n+++ b/file.py"


def test_fetch_pr_diff_uses_bearer_token():
    with patch("main.requests.get") as mock_get:
        mock_get.return_value = MagicMock(text="diff", raise_for_status=MagicMock())
        fetch_pr_diff("org/repo", 1, "my-token")

    headers = mock_get.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer my-token"


def test_fetch_pr_diff_requests_diff_media_type():
    with patch("main.requests.get") as mock_get:
        mock_get.return_value = MagicMock(text="diff", raise_for_status=MagicMock())
        fetch_pr_diff("org/repo", 1, "token")

    headers = mock_get.call_args.kwargs["headers"]
    assert headers["Accept"] == "application/vnd.github.v3.diff"


# --- extract_changed_python_files ---

def _files_response(*entries):
    mock = MagicMock()
    mock.json.return_value = list(entries)
    return mock


def test_extract_returns_only_python_files():
    with patch("main.requests.get", return_value=_files_response(
        {"filename": "auth.py", "status": "modified"},
        {"filename": "README.md", "status": "modified"},
        {"filename": "utils.py", "status": "added"},
    )):
        result = extract_changed_python_files("token", "org/repo", 1)
    assert result == ["auth.py", "utils.py"]


def test_extract_skips_removed_files():
    with patch("main.requests.get", return_value=_files_response(
        {"filename": "old.py", "status": "removed"},
        {"filename": "new.py", "status": "added"},
    )):
        result = extract_changed_python_files("token", "org/repo", 1)
    assert result == ["new.py"]


def test_extract_returns_empty_when_no_python_files():
    with patch("main.requests.get", return_value=_files_response(
        {"filename": "config.yml", "status": "modified"},
    )):
        result = extract_changed_python_files("token", "org/repo", 1)
    assert result == []


# --- write_changed_files_locally ---

def _make_get_side_effect(files_response_list, file_content="# code"):
    def side_effect(url, **kwargs):
        response = MagicMock(status_code=200)
        if "/files" in url:
            response.json.return_value = files_response_list
        else:
            response.text = file_content
        return response
    return side_effect


def test_write_changed_files_calls_pr_files_api_exactly_once(tmp_path):
    files = [
        {"filename": "auth.py", "raw_url": "https://raw.example.com/auth.py"},
        {"filename": "utils.py", "raw_url": "https://raw.example.com/utils.py"},
    ]
    with patch("main.requests.get", side_effect=_make_get_side_effect(files)) as mock_get:
        write_changed_files_locally(["auth.py", "utils.py"], "org/repo", 1, "token", str(tmp_path))

    files_api_calls = [c for c in mock_get.call_args_list if "/files" in c[0][0]]
    assert len(files_api_calls) == 1, "PR files API must be called once, not once per file"


def test_write_changed_files_downloads_each_file(tmp_path):
    files = [
        {"filename": "auth.py", "raw_url": "https://raw.example.com/auth.py"},
        {"filename": "utils.py", "raw_url": "https://raw.example.com/utils.py"},
    ]
    with patch("main.requests.get", side_effect=_make_get_side_effect(files, "# content")):
        result = write_changed_files_locally(["auth.py", "utils.py"], "org/repo", 1, "token", str(tmp_path))

    assert len(result) == 2
    for path in result:
        assert path.endswith(".py")


def test_write_changed_files_skips_missing_raw_url(tmp_path):
    files = [
        {"filename": "auth.py", "raw_url": ""},
        {"filename": "utils.py", "raw_url": "https://raw.example.com/utils.py"},
    ]
    with patch("main.requests.get", side_effect=_make_get_side_effect(files)):
        result = write_changed_files_locally(["auth.py", "utils.py"], "org/repo", 1, "token", str(tmp_path))

    assert len(result) == 1
    assert result[0].endswith("utils.py")


def test_write_changed_files_skips_non_200_responses(tmp_path):
    files = [{"filename": "auth.py", "raw_url": "https://raw.example.com/auth.py"}]

    def side_effect(url, **kwargs):
        response = MagicMock()
        if "/files" in url:
            response.status_code = 200
            response.json.return_value = files
        else:
            response.status_code = 404
        return response

    with patch("main.requests.get", side_effect=side_effect):
        result = write_changed_files_locally(["auth.py"], "org/repo", 1, "token", str(tmp_path))

    assert result == []
