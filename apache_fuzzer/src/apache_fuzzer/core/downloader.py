"""Download and extract Apache HTTPD source and its bundled dependencies.

Handles fetching the HTTPD tarball from the Apache mirror (with archive
fallback), plus APR, APR-Util, and Expat which are placed into
``srclib/`` for a ``--with-included-apr`` build.
"""

import os
import requests
import tarfile
from pathlib import Path
from typing import Optional
from apache_fuzzer.config import Config
from apache_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class Downloader:
    """Fetch and unpack Apache HTTPD, APR, APR-Util, and Expat."""

    def __init__(self) -> None:
        self.mirror = Config.APACHE_MIRROR
        self.archive = Config.APACHE_ARCHIVE
        self.work_dir = Config.WORK_DIR

    def download_apache(self, version: Optional[str] = None) -> Path:
        """Download Apache HTTPD and its bundled dependencies.

        Parameters
        ----------
        version : str, optional
            Version to download (e.g. ``"2.4.62"``).  Defaults to
            :attr:`Config.DEFAULT_APACHE_VERSION`.

        Returns
        -------
        Path
            Directory containing the extracted source tree.
        """
        if not version:
            version = Config.DEFAULT_APACHE_VERSION
        
        target_dir = self.work_dir / f"httpd-{version}"

        if target_dir.exists():
            # Check if dependencies exist
            deps_exist = True
            if not (target_dir / "srclib" / "apr").exists():
                deps_exist = False
            if not (target_dir / "srclib" / "apr-util").exists():
                deps_exist = False
            
            # Check Expat (inside apr-util)
            expat_dir = target_dir / "srclib" / "apr-util" / "xml" / "expat"
            if not expat_dir.exists():
                deps_exist = False

            if deps_exist:
                logger.warning(f"Directory {target_dir} and dependencies already exist. Skipping download.")
                return target_dir
            else:
                 logger.warning(f"Directory {target_dir} exists but dependencies missing. Downloading dependencies...")
                 self._download_dependencies(target_dir)
                 return target_dir

        tarball = f"httpd-{version}.tar.gz"
        url = f"{self.mirror}/{tarball}"
        
        logger.info(f"Downloading Apache HTTPD {version} from {url}...")
        try:
            self._download_file(url, tarball)
        except Exception:
            # Fallback to archive
            url = f"{self.archive}/{tarball}"
            logger.warning(f"Mirror failed. Trying archive: {url}")
            self._download_file(url, tarball)

        logger.info("Extracting...")
        with tarfile.open(tarball, "r:gz") as tar:
            tar.extractall(path=self.work_dir)
        
        os.remove(tarball)
        
        # Download APR/APR-Util
        self._download_dependencies(target_dir)
        
        logger.info(f"Apache HTTPD {version} downloaded to {target_dir}")
        return target_dir

    def _download_dependencies(self, httpd_root: Path) -> None:
        srclib = httpd_root / "srclib"
        srclib.mkdir(exist_ok=True)
        
        # APR
        if not (srclib / "apr").exists():
            self._download_and_extract(
                "https://dlcdn.apache.org/apr/apr-1.7.6.tar.gz",
                srclib / "apr",
                strip_components=1
            )
        
        # APR-Util
        if not (srclib / "apr-util").exists():
            self._download_and_extract(
                "https://dlcdn.apache.org/apr/apr-util-1.6.3.tar.gz",
                srclib / "apr-util",
                strip_components=1
            )
            
        # Expat (Bundled)
        xml_dir = srclib / "apr-util" / "xml"
        xml_dir.mkdir(exist_ok=True)
        
        expat_dir = xml_dir / "expat"
        if not expat_dir.exists():
            self._download_and_extract(
                "https://github.com/libexpat/libexpat/releases/download/R_2_6_4/expat-2.6.4.tar.gz",
                expat_dir,
                strip_components=1
            )

    def _download_and_extract(self, url: str, target_dir: Path, strip_components: int = 0) -> None:
        filename = url.split("/")[-1]
        logger.info(f"Downloading {filename}...")
        self._download_file(url, filename)
        
        # target_dir.mkdir(parents=True, exist_ok=True) # Unnecessary and causes issues with rename
        
        logger.info(f"Extracting to {target_dir}...")
        with tarfile.open(filename, "r:gz") as tar:
            tar.extractall(path=target_dir.parent)
            
            extracted_name = filename.replace(".tar.gz", "")
            extracted_path = target_dir.parent / extracted_name
            
            if extracted_path.exists() and extracted_path != target_dir:
                if target_dir.exists():
                    import shutil
                    if target_dir.is_dir():
                        shutil.rmtree(target_dir)
                    else:
                        target_dir.unlink()
                
                extracted_path.rename(target_dir)

        os.remove(filename)

    def _download_file(self, url: str, filename: str) -> None:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192): 
                    f.write(chunk)
