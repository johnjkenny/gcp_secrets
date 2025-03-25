from pathlib import Path


from gcp_secrets.secrets import GCPSecrets


class Init(GCPSecrets):
    def __init__(self, sa_path: str, default: bool = False, force: bool = False):
        """Initialize the GCP Secret Manager environment. This will generate the cipher key and create the service
        account file and encrypt it with the cipher key.

        Args:
            sa_path (str): The path to the service account json file
            default (bool, optional): option to set the service account as default. Defaults to False.
            force (bool, optional): force actions. Defaults to False.

        Raises:
            FileNotFoundError: if the service account file is not found
        """
        super().__init__()
        self.__sa_path = Path(sa_path)
        if not self.__sa_path.exists():
            raise FileNotFoundError(f'File not found: {self.__sa_path}')
        self.__default = default
        self.__force = force

    def __create_env_key(self) -> bool:
        """Create the cipher key for encryption/decryption

        Returns:
            bool: True if the key was created successfully, False otherwise
        """
        if self.__force or not Path(self.cipher.key_file).exists():
            return self.cipher._create_key()
        return True

    def __set_default_service_account(self) -> bool:
        """Set the default service account

        Returns:
            bool: True if the service account was set successfully, False otherwise
        """
        try:
            with open(self.default_sa, 'w') as file:
                file.write(self.service_account)
            return True
        except Exception:
            self.log.exception('Failed to set default service account')
        return False

    def __create_credentials(self) -> bool:
        """Create the service account file and encrypt it with the cipher key

        Returns:
            bool: True if the service account file was created successfully, False otherwise
        """
        sa = self._load_json_service_account(self.__sa_path)
        if sa:
            self.service_account = sa.get('client_email', '').split('@')[0]
            if self.__default or not Path(self.default_sa).exists():
                if not self.__set_default_service_account():
                    return False
            if self.__force or not Path(self.sa_file).exists():
                return self._create_service_account_file(self.sa_file, sa)
            self.log.info('Credentials file already exists. Use --force to overwrite if needed')
            return True
        return False

    def _run(self) -> bool:
        """Run the initialization process

        Returns:
            bool: True if the initialization was successful, False otherwise
        """
        for method in [self.__create_env_key, self.__create_credentials]:
            if not method():
                return False
        return True
