"""Tests for apatchy.managers.config_manager.ConfigManager flag generation."""


from apatchy.managers.config_manager import ConfigManager

# --- fuzz mode ---

def test_fuzz_mode_cc():
    """Fuzz mode sets CC to afl-clang-fast."""
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config()
    assert result["CC"] == "afl-clang-fast"


def test_fuzz_mode_debug_flags():
    """Fuzz mode includes -g -O0 -fno-omit-frame-pointer."""
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config()
    assert "-g" in result["CFLAGS"]
    assert "-O0" in result["CFLAGS"]
    assert "-fno-omit-frame-pointer" in result["CFLAGS"]


def test_fuzz_mode_suppresses_format_warning():
    """Fuzz mode adds -Wno-error=format for clang compatibility."""
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config()
    assert "-Wno-error=format" in result["CFLAGS"]


# --- coverage mode ---

def test_coverage_mode_flags():
    """Coverage mode adds profile and coverage-mapping flags."""
    cm = ConfigManager(build_mode="coverage")
    result = cm.generate_build_config()
    assert "-fprofile-instr-generate" in result["CFLAGS"]
    assert "-fcoverage-mapping" in result["CFLAGS"]


def test_coverage_mode_ldflags():
    """Coverage mode adds profile and -no-pie to LDFLAGS."""
    cm = ConfigManager(build_mode="coverage")
    result = cm.generate_build_config()
    assert "-fprofile-instr-generate" in result["LDFLAGS"]
    assert "-no-pie" in result["LDFLAGS"]


def test_coverage_mode_no_cc():
    """Coverage mode does not override CC."""
    cm = ConfigManager(build_mode="coverage")
    result = cm.generate_build_config()
    assert "CC" not in result


# --- sanitizers ---

def test_asan():
    """ASan flag adds -fsanitize=address to CFLAGS and LDFLAGS."""
    cm = ConfigManager(build_mode="fuzz", asan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=address" in result["CFLAGS"]
    assert "-fsanitize=address" in result["LDFLAGS"]


def test_ubsan():
    """UBSan flag adds -fsanitize=undefined."""
    cm = ConfigManager(build_mode="fuzz", ubsan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=undefined" in result["CFLAGS"]
    assert "-fsanitize=undefined" in result["LDFLAGS"]


def test_intsan():
    """IntSan flag adds -fsanitize=unsigned-integer-overflow."""
    cm = ConfigManager(build_mode="fuzz", intsan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=unsigned-integer-overflow" in result["CFLAGS"]
    assert "-fsanitize=unsigned-integer-overflow" in result["LDFLAGS"]


def test_intsan_with_ignorelist(tmp_path, monkeypatch):
    """IntSan applies -fsanitize-ignorelist when ignorelist file exists."""
    ignorelist = tmp_path / "configs" / "intsan.ignorelist"
    ignorelist.parent.mkdir()
    ignorelist.write_text("[unsigned-integer-overflow]\nsrc:*/apr_hash.c\n")
    monkeypatch.chdir(tmp_path)

    cm = ConfigManager(build_mode="fuzz", intsan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=unsigned-integer-overflow" in result["CFLAGS"]
    assert f"-fsanitize-ignorelist={ignorelist.resolve()}" in result["CFLAGS"]


def test_intsan_without_ignorelist(tmp_path, monkeypatch):
    """IntSan works without ignorelist (just no ignorelist flag)."""
    monkeypatch.chdir(tmp_path)
    from apatchy.config import Config
    monkeypatch.setattr(Config, "PROJECT_ROOT", tmp_path)

    cm = ConfigManager(build_mode="fuzz", intsan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=unsigned-integer-overflow" in result["CFLAGS"]
    assert "-fsanitize-ignorelist" not in result["CFLAGS"]


def test_truncsan():
    """TruncSan flag adds -fsanitize=implicit-unsigned-integer-truncation."""
    cm = ConfigManager(build_mode="fuzz", truncsan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=implicit-unsigned-integer-truncation" in result["CFLAGS"]
    assert "-fsanitize=implicit-unsigned-integer-truncation" in result["LDFLAGS"]


def test_combined_asan_ubsan():
    """ASan + UBSan flags coexist without conflicts."""
    cm = ConfigManager(build_mode="fuzz", asan=True, ubsan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=address" in result["CFLAGS"]
    assert "-fsanitize=undefined" in result["CFLAGS"]
    assert "-fsanitize=address" in result["LDFLAGS"]
    assert "-fsanitize=undefined" in result["LDFLAGS"]


def test_all_sanitizers():
    """All four sanitizer flags present together."""
    cm = ConfigManager(build_mode="fuzz", asan=True, ubsan=True, intsan=True, truncsan=True)
    result = cm.generate_build_config()
    cflags = result["CFLAGS"]
    assert "-fsanitize=address" in cflags
    assert "-fsanitize=undefined" in cflags
    assert "-fsanitize=unsigned-integer-overflow" in cflags
    assert "-fsanitize=implicit-unsigned-integer-truncation" in cflags


def test_fuzz_mode_no_pie():
    """Fuzz mode adds -no-pie for SanCov non-PIC relocations."""
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config()
    assert "-no-pie" in result["LDFLAGS"]


# --- coverage + sanitizers ---

def test_coverage_with_asan():
    """Coverage mode + ASan combines both flag sets."""
    cm = ConfigManager(build_mode="coverage", asan=True)
    result = cm.generate_build_config()
    assert "-fprofile-instr-generate" in result["CFLAGS"]
    assert "-fsanitize=address" in result["CFLAGS"]
    assert "CC" not in result


# --- config path resolution ---

def test_get_httpd_config_direct_path(tmp_path):
    """get_httpd_config resolves a direct file path."""
    conf = tmp_path / "test.conf"
    conf.write_text("ServerRoot /tmp\n")
    cm = ConfigManager(config_name=str(conf))
    result = cm.get_httpd_config()
    assert result == conf.resolve()


def test_get_httpd_config_missing():
    """get_httpd_config returns None for missing config."""
    cm = ConfigManager(config_name="nonexistent_config_12345.conf")
    result = cm.get_httpd_config()
    assert result is None


def test_get_httpd_config_override(tmp_path):
    """get_httpd_config(config_name=...) overrides the default."""
    conf = tmp_path / "override.conf"
    conf.write_text("Listen 8080\n")
    cm = ConfigManager(config_name="fuzz.conf")
    result = cm.get_httpd_config(config_name=str(conf))
    assert result == conf.resolve()
