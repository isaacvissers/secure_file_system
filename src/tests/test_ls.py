import main as main_module
from main import SecureFS
from tests.test_login import _make_user_data

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _logged_in_shell(tmp_path, monkeypatch):
    """Return a SecureFS instance with cwd set to FILES_DIR/alice."""
    monkeypatch.setattr(main_module, "FILES_DIR", tmp_path)
    user_home = tmp_path / "alice"
    user_home.mkdir(exist_ok=True)
    shell = SecureFS()
    shell.current_user = _make_user_data(user_id=1, username="alice")
    shell.current_working_directory = user_home
    shell._update_prompt()
    return shell


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_ls_empty_directory(tmp_path, monkeypatch, capsys):
    """ls prints nothing when the directory is empty."""
    shell = _logged_in_shell(tmp_path, monkeypatch)

    shell.do_ls("")

    captured = capsys.readouterr()
    assert captured.out == ""


def test_ls_shows_directory_with_trailing_slash(tmp_path, monkeypatch, capsys):
    """ls prints directories with a trailing '/'."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    (tmp_path / "alice" / "docs").mkdir()

    shell.do_ls("")

    captured = capsys.readouterr()
    assert "docs/" in captured.out


def test_ls_shows_file_without_json_extension(tmp_path, monkeypatch, capsys):
    """ls strips the .json extension when displaying files."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    (tmp_path / "alice" / "notes.json").write_text("{}")

    shell.do_ls("")

    captured = capsys.readouterr()
    assert "notes" in captured.out
    assert "notes.json" not in captured.out


def test_ls_hides_json_file_when_matching_directory_exists(
    tmp_path, monkeypatch, capsys
):
    """ls hides a .json file when a directory with the same stem exists."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    (tmp_path / "alice" / "docs").mkdir()
    (tmp_path / "alice" / "docs.json").write_text("{}")

    shell.do_ls("")

    captured = capsys.readouterr()
    assert "docs/" in captured.out
    assert "docs.json" not in captured.out
    # 'docs' should appear exactly once (as the directory)
    assert captured.out.count("docs") == 1


def test_ls_shows_json_file_without_matching_directory(tmp_path, monkeypatch, capsys):
    """ls shows a .json file (without extension) when no matching directory exists."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    (tmp_path / "alice" / "report.json").write_text("{}")

    shell.do_ls("")

    captured = capsys.readouterr()
    assert "report" in captured.out
    assert "report.json" not in captured.out


def test_ls_mixed_entries(tmp_path, monkeypatch, capsys):
    """ls correctly handles a mix of directories and files."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    (tmp_path / "alice" / "images").mkdir()
    (tmp_path / "alice" / "images.json").write_text("{}")  # should be hidden
    (tmp_path / "alice" / "readme.json").write_text("{}")  # should appear as 'readme'

    shell.do_ls("")

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert "images/" in lines
    assert "readme" in lines
    assert "images.json" not in captured.out
    # images.json must NOT appear as a standalone entry (only as "images/")
    assert not any(l.strip() == "images" for l in lines)


def test_ls_multiple_files(tmp_path, monkeypatch, capsys):
    """ls lists all files (stripped of .json) when no matching directories exist."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    for name in ("alpha", "beta", "gamma"):
        (tmp_path / "alice" / f"{name}.json").write_text("{}")

    shell.do_ls("")

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert "alpha" in lines
    assert "beta" in lines
    assert "gamma" in lines


def test_ls_multiple_directories(tmp_path, monkeypatch, capsys):
    """ls lists all subdirectories with trailing slashes."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    for name in ("music", "videos", "photos"):
        (tmp_path / "alice" / name).mkdir()

    shell.do_ls("")

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert "music/" in lines
    assert "videos/" in lines
    assert "photos/" in lines


def test_ls_works_in_subdirectory(tmp_path, monkeypatch, capsys):
    """ls works correctly when cwd is a subdirectory of the user home."""
    shell = _logged_in_shell(tmp_path, monkeypatch)
    subdir = tmp_path / "alice" / "projects"
    subdir.mkdir()
    (subdir / "plan.json").write_text("{}")
    shell.current_working_directory = subdir

    shell.do_ls("")

    captured = capsys.readouterr()
    assert "plan" in captured.out
    assert "plan.json" not in captured.out
