"""Tests for apatchy.managers.config_manager.ConfigManager flag generation."""

from pathlib import Path

from apatchy.managers.config_manager import ConfigManager


# --- fuzz mode ---

def test_fuzz_mode_cc():
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config()
    assert result["CC"] == "afl-clang-fast"


def test_fuzz_mode_debug_flags():
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config()
    assert "-g" in result["CFLAGS"]
    assert "-O0" in result["CFLAGS"]
    assert "-fno-omit-frame-pointer" in result["CFLAGS"]


def test_fuzz_mode_suppresses_format_warning():
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config()
    assert "-Wno-error=format" in result["CFLAGS"]


# --- coverage mode ---

def test_coverage_mode_flags():
    cm = ConfigManager(build_mode="coverage")
    result = cm.generate_build_config()
    assert "-fprofile-instr-generate" in result["CFLAGS"]
    assert "-fcoverage-mapping" in result["CFLAGS"]


def test_coverage_mode_ldflags():
    cm = ConfigManager(build_mode="coverage")
    result = cm.generate_build_config()
    assert "-fprofile-instr-generate" in result["LDFLAGS"]
    assert "-no-pie" in result["LDFLAGS"]


def test_coverage_mode_no_cc():
    cm = ConfigManager(build_mode="coverage")
    result = cm.generate_build_config()
    assert "CC" not in result


# --- sanitizers ---

def test_asan():
    cm = ConfigManager(build_mode="fuzz", asan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=address" in result["CFLAGS"]
    assert "-fsanitize=address" in result["LDFLAGS"]


def test_ubsan():
    cm = ConfigManager(build_mode="fuzz", ubsan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=undefined" in result["CFLAGS"]
    assert "-fsanitize=undefined" in result["LDFLAGS"]


def test_intsan():
    cm = ConfigManager(build_mode="fuzz", intsan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=unsigned-integer-overflow" in result["CFLAGS"]
    assert "-fsanitize=unsigned-integer-overflow" in result["LDFLAGS"]


def test_truncsan():
    cm = ConfigManager(build_mode="fuzz", truncsan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=implicit-unsigned-integer-truncation" in result["CFLAGS"]
    assert "-fsanitize=implicit-unsigned-integer-truncation" in result["LDFLAGS"]


def test_combined_asan_ubsan():
    cm = ConfigManager(build_mode="fuzz", asan=True, ubsan=True)
    result = cm.generate_build_config()
    assert "-fsanitize=address" in result["CFLAGS"]
    assert "-fsanitize=undefined" in result["CFLAGS"]
    assert "-fsanitize=address" in result["LDFLAGS"]
    assert "-fsanitize=undefined" in result["LDFLAGS"]


def test_all_sanitizers():
    cm = ConfigManager(build_mode="fuzz", asan=True, ubsan=True, intsan=True, truncsan=True)
    result = cm.generate_build_config()
    cflags = result["CFLAGS"]
    assert "-fsanitize=address" in cflags
    assert "-fsanitize=undefined" in cflags
    assert "-fsanitize=unsigned-integer-overflow" in cflags
    assert "-fsanitize=implicit-unsigned-integer-truncation" in cflags


def test_no_sanitizers_empty_ldflags():
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config()
    # LDFLAGS should be empty string when no sanitizers and fuzz mode
    assert result["LDFLAGS"] == ""


# --- coverage + sanitizers ---

def test_coverage_with_asan():
    cm = ConfigManager(build_mode="coverage", asan=True)
    result = cm.generate_build_config()
    assert "-fprofile-instr-generate" in result["CFLAGS"]
    assert "-fsanitize=address" in result["CFLAGS"]
    assert "CC" not in result


# --- config path resolution ---

def test_get_httpd_config_direct_path(tmp_path):
    conf = tmp_path / "test.conf"
    conf.write_text("ServerRoot /tmp\n")
    cm = ConfigManager(config_name=str(conf))
    result = cm.get_httpd_config()
    assert result == conf.resolve()


def test_get_httpd_config_missing():
    cm = ConfigManager(config_name="nonexistent_config_12345.conf")
    result = cm.get_httpd_config()
    assert result is None


def test_get_httpd_config_override(tmp_path):
    conf = tmp_path / "override.conf"
    conf.write_text("Listen 8080\n")
    cm = ConfigManager(config_name="fuzz.conf")
    result = cm.get_httpd_config(config_name=str(conf))
    assert result == conf.resolve()
