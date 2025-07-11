import platform
from dataclasses import dataclass
from functools import cached_property


@dataclass
class Release:
    """
    Represents a software release hosted on Github
    """

    repo_url: str
    app_name: str
    app_version: str

    def __init__(self, repo_url: str, app_version: str, app_name: str | None = None) -> None:
        # Extract the application name from the repository URL
        app_name = app_name or repo_url.rstrip('/').split('/')[-1]

        self.repo_url = repo_url
        self.app_name = app_name
        self.app_version = app_version

    @property
    def binary_name(self) -> str:
        """
        Returns the OS-specific binary name.
        """
        # On Windows, we need to to include .exe extension
        if platform.system() == 'Windows':
            return f'{self.app_name}.exe'

        return self.app_name

    @cached_property
    def binary_url(self) -> str:
        """
        Returns the URL of binary based on the current OS and architecture.

        Full URL example:
        https://github.com/paradigmxyz/reth/releases/download/v1.5.1/reth-v1.5.1-aarch64-unknown-linux-gnu.tar.gz

        File name examples:
        Linux
        * reth-v1.5.1-aarch64-unknown-linux-gnu.tar.gz
        * reth-v1.5.1-x86_64-unknown-linux-gnu.tar.gz
        Windows
        * reth-v1.5.1-x86_64-pc-windows-gnu.tar.gz
        macOS
        * reth-v1.5.1-aarch64-apple-darwin.tar.gz
        * reth-v1.5.1-x86_64-apple-darwin.tar.gz
        """

        # Get environment details
        os_name = platform.system()
        arch = platform.machine()

        # Map OS names to the expected format for Github
        os_map = {
            'Linux': 'unknown-linux-gnu',
            'Darwin': 'apple-darwin',
            'Windows': 'pc-windows-gnu',
        }

        # Map architecture names to the expected format for Github
        arch_map = {
            'x86_64': 'x86_64',
            'arm64': 'aarch64',
        }

        # Build the file name based on the version, OS and architecture
        archive_name = (
            f'{self.app_name}-{self.app_version}-{arch_map[arch]}-{os_map[os_name]}.tar.gz'
        )

        # Build the full URL for the Reth binary
        return f'{self.repo_url}/releases/download/{self.app_version}/{archive_name}'
