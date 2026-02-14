import os
from pathlib import Path

class Config:
    PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.resolve()
    APACHE_MIRROR = "https://dlcdn.apache.org/httpd"
    APACHE_ARCHIVE = "https://archive.apache.org/dist/httpd"
    
    # Directories
    WORK_DIR = Path(os.getcwd())
    SRC_DIR = PROJECT_ROOT / "src" / "apache_fuzzer"
    TOOLCHAIN_DIR = WORK_DIR / "toolchain"
    
    # Defaults
    DEFAULT_APACHE_VERSION = "2.4.62"

    # Toolchain config
    TOOLCHAIN_CONFIG = WORK_DIR / "toolchain.config"

    # AFL++ / Mutators
    AFLPP_REPO_URL = "https://github.com/AFLplusplus/AFLplusplus"
    GRAMMARS_DIR = Path(__file__).parent / "grammars"
    CUSTOM_MUTATORS_DIR = Path(__file__).parent / "custom_mutators"
    HARNESSES_DIR = Path(__file__).parent / "harnesses"
    EXTERNAL_MODULES_DIR = Path(__file__).parent / "external_modules"
    DEV_DIR = WORK_DIR / "dev"
    
    @classmethod
    def get_apache_dir(cls, version: str) -> Path:
        return cls.WORK_DIR / f"httpd-{version}"
