from pathlib import Path
from getpass import getpass
from pickle import loads, dumps
from json import load
from os import remove

from google.api_core.exceptions import NotFound, FailedPrecondition, InvalidArgument
from google.cloud.secretmanager import SecretManagerServiceClient
from google.oauth2 import service_account

from gcp_secrets.logger import get_logger
from gcp_secrets.encrypt import Cipher
from gcp_secrets.color import Color


class GCPSecrets():
    def __init__(self, service_account: str = 'default', project_id: str = ''):
        self.log = get_logger('gcp-secrets')
        self.service_account = service_account
        self.project_id = project_id
        self.__client: SecretManagerServiceClient | None = None
        self.__cipher: Cipher | None = None

    @property
    def default_sa(self):
        return f'{Path(__file__).parent}/gcp_env/default_sa'

    @property
    def sa_file(self):
        if self.service_account == 'default':
            self.service_account = self.__get__default_service_account()
        return f'{Path(__file__).parent}/gcp_env/.{self.service_account}.sa'

    @property
    def secret_object_path(self):
        return f'projects/{self.project_id}'

    @property
    def cipher(self):
        if self.__cipher is None:
            self.__cipher = Cipher(self.log)
        return self.__cipher

    @property
    def creds(self):
        try:
            with open(self.sa_file, 'rb') as file:
                __creds: dict = loads(self.cipher.decrypt(file.read(), self.cipher.load_key()))
            if not self.project_id:
                self.project_id = __creds.get('project_id', '')
            return service_account.Credentials.from_service_account_info(__creds)
        except Exception:
            self.log.exception('Failed to load credentials')
        return None

    @property
    def client(self):
        if self.__client is None:
            try:
                self.__client = SecretManagerServiceClient(credentials=self.creds)
            except Exception:
                self.log.exception('Failed to load secret client')
        return self.__client

    @staticmethod
    def display_success(msg: str):
        Color().print_message(msg, 'green')

    @staticmethod
    def display_failed(msg: str):
        Color().print_message(msg, 'red')

    def _prompt_for_passwd(self) -> str:
        """Prompt for a password on console without echoing

        Returns:
            str: password provided
        """
        passwd = getpass('Enter password: ')
        if not passwd:
            self.log.error('Password cannot be empty')
            return self._prompt_for_passwd()
        return passwd

    def _create_service_account_file(self, sa_file: str, sa_data: dict):
        try:
            with open(sa_file, 'wb') as file:
                file.write(self.cipher.encrypt(dumps(sa_data), self.cipher.load_key()))
            return True
        except Exception:
            self.log.exception('Failed to create service account file')
        return False

    def _load_json_service_account(self, sa_path: str) -> dict:
        try:
            with open(sa_path, 'r') as sa_file:
                return load(sa_file)
        except Exception:
            self.log.exception('Failed to create credentials file')
        return {}

    def get_secret_name(self, secret_name: str) -> str:
        """Get the full path of a secret object.

        Args:
            secret_name (str): name of the secret object

        Returns:
            str: full path of the secret object- projects/{project_id}/secrets/{secret_name}
        """
        return f'{self.secret_object_path}/secrets/{secret_name}'

    def get_version_name(self, secret_name: str, version: str) -> str:
        """Get the full path of a secret version.

        Args:
            secret_name (str): name of the secret object
            version (str): secret version

        Returns:
            str: full path of the secret version- projects/{project_id}/secrets/{secret_name}/versions/{version}
        """
        return f'{self.get_secret_name(secret_name)}/versions/{version}'

    def __create_secret_object(self, secret_name: str):
        """Create a secret object for secret versions to be stored in.

        Args:
            secret_name (str): name of the secret object

        Returns:
            bool: True if successful, False otherwise
        """
        if self.secret_exists(secret_name):
            return True
        try:
            request = {'parent': self.secret_object_path, 'secret_id': secret_name,
                       'secret': {'replication': {'automatic': {}}}}
            self.client.create_secret(request=request)
            self.log.info(f'Created secret object {secret_name}')
            return True
        except Exception:
            self.log.exception(f'Failed to create secret object {secret_name}')
        return False

    def __get__default_service_account(self):
        try:
            with open(self.default_sa, 'r') as file:
                return file.read().strip()
        except Exception:
            self.log.exception('Failed to load default service account')
        return ''

    def add_secret_version(self, secret_name: str, payload: bytes, passwd: bool = False):
        """Add a secret version to an existing secret object.

        Args:
            secret_name (str): name of the secret object
            payload (object): data to store in the secret object
            passwd (bool, optional): True if the payload is a password. Defaults to False.

        Returns:
            bool: True if successful, False otherwise
        """
        if self.client:
            if passwd:
                payload = self.cipher.passwd_xor(payload, self._prompt_for_passwd())
            try:
                request = {'parent': self.get_secret_name(secret_name), 'payload': {'data': payload}}
                self.client.add_secret_version(request=request)
                self.log.info(f'Added secret version to secret object {secret_name}')
                return True
            except Exception:
                self.log.exception(f'Failed to add secret version to secret object {secret_name}')
        return False

    def create_secret(self, secret_name: str, payload: bytes, passwd: bool = False):
        """Create a secret object and add a secret version to it. If the secret object already exists, only add a secret
        version to it making it the latest secret version.

        Args:
            secret_name (str): name of the secret object
            payload (bytes): data to store in the secret object
            passwd (bool, optional): True if the payload is a password. Defaults to False.

        Returns:
            bool: True if successful, False otherwise
        """
        return self.__create_secret_object(secret_name) and self.add_secret_version(secret_name, payload, passwd)

    def create_secret_from_file(self, secret_name: str, file_path: str, passwd: bool = False):
        path = Path(file_path)
        if path.exists():
            try:
                with open(path, 'rb') as file:
                    data = file.read()
            except Exception:
                self.log.exception(f'Failed to get secret data from file {file_path}')
                return False
            return self.create_secret(secret_name, data, passwd)
        self.log.error(f'File not found: {file_path}')
        return False

    def get_secret(self, secret_name: str, passwd: bool = False, version: str = 'latest', display: bool = False):
        """Pull secret version data from a secret object.

        Args:
            secret_name (str): name of the secret object
            passwd (bool, optional): True if the payload is a password. Defaults to False.
            version (str, optional): secret version to pull. Defaults to 'latest'.

        Returns:
            object: secret version data or None if failed
        """
        rsp = None
        if self.client:
            try:
                rsp = self.client.access_secret_version(request={'name': self.get_version_name(secret_name, version)})
            except NotFound:
                self.log.error(f'Secret version {version} not found in secret object {secret_name}')
            except FailedPrecondition as error:
                if error.code == 400:
                    self.log.error(f'Secret version {version} is not enabled in secret object {secret_name}')
            except Exception:
                self.log.exception(f'Failed to get secret version {version} from secret object {secret_name}')
        if rsp:
            if passwd:
                data = self.cipher.passwd_xor(rsp.payload.data, self._prompt_for_passwd())
            else:
                data = rsp.payload.data
            if display:
                try:
                    self.display_success(data.decode())
                except UnicodeDecodeError:
                    self.log.error('Failed to decrypt secret data')
                    return None
            return data
        return None

    def get_secret_to_file(self, secret_name: str, file_path: str, passwd: bool = False, version: str = 'latest'):
        data = self.get_secret(secret_name, passwd, version)
        if data:
            try:
                with open(file_path, 'wb') as file:
                    file.write(data)
                return True
            except Exception:
                self.log.exception(f'Failed to write secret data to file {file_path}')
        return False

    def delete_secret(self, secret_name: str):
        """Delete a secret object.

        Args:
            secret_name (str): name of secret object

        Returns:
            bool: True if successful, False otherwise
        """
        if self.client:
            try:
                self.client.delete_secret(request={'name': self.get_secret_name(secret_name)})
                self.log.info(f'Deleted secret object {secret_name}')
                return True
            except NotFound:
                self.log.error(f'Secret object {secret_name} does not exists to delete')
                return True
            except Exception:
                self.log.exception(f'Failed to delete secret object {secret_name}')
        return False

    def delete_secret_version(self, secret_name: str, version: str):
        """Delete a secret version from a secret object.

        Args:
            secret_name (str): secret object name
            version (str): secret version to delete

        Returns:
            bool: True if successful, False otherwise
        """
        if self.client:
            try:
                self.client.destroy_secret_version(request={'name': self.get_version_name(secret_name, version)})
                self.log.info(f'Deleted secret version {version} from secret object {secret_name}')
                return True
            except NotFound:
                self.log.error(f'Secret version {version} not found in secret object {secret_name}')
            except FailedPrecondition as error:
                self.log.error(error.message)
            except InvalidArgument as error:
                self.log.error(error.message)
            except Exception:
                self.log.exception(f'Failed to delete secret version {version} from secret object {secret_name}')
        return False

    def disable_secret_version(self, secret_name: str, version: int):
        """Disable a secret version from a secret object.

        Args:
            secret_name (str): secret object name
            version (str): secret version to disable

        Returns:
            bool: True if successful, False otherwise
        """
        if self.client:
            try:
                request = {'name': self.get_version_name(secret_name, version)}
                self.client.disable_secret_version(request=request)
                self.log.info(f'Disabled secret version {version} from secret object {secret_name}')
                return True
            except NotFound:
                self.log.error(f'Secret version {version} not found in secret object {secret_name}')
                return True
            except Exception:
                self.log.exception(f'Failed to disable secret version {version} from secret object {secret_name}')
        return False

    def enable_secret_version(self, secret_name: str, version: str):
        """Enable a secret version from a secret object.

        Args:
            secret_name (str): secret object name
            version (str): version to enable

        Returns:
            bool: True if successful, False otherwise
        """
        if self.client:
            try:
                self.client.enable_secret_version(request={'name': self.get_version_name(secret_name, version)})
                self.log.info(f'Enabled secret version {version} from secret object {secret_name}')
                return True
            except NotFound:
                self.log.error(f'Secret version {version} not found in secret object {secret_name}')
                return True
            except Exception:
                self.log.exception(f'Failed to enable secret version {version} from secret object {secret_name}')
        return False

    def secret_exists(self, secret_name: str):
        """Check if a secret object exists.

        Args:
            secret_name (str): name of the secret object

        Returns:
            bool: True if exists, False otherwise
        """
        if self.client:
            try:
                self.client.get_secret(request={'name': self.get_secret_name(secret_name)})
                return True
            except NotFound:
                return False
            except Exception:
                self.log.exception(f'Failed to check if secret object {secret_name} exists')
        return False

    def get_latest_secret_version(self, secret_name: str):
        """Get the latest secret version from a secret object.

        Args:
            secret_name (str): name of the secret object

        Returns:
            int: latest secret version number. 0 if failed
        """
        versions = []
        try:
            for version in self.client.list_secret_versions(request={'parent': self.get_secret_name(secret_name)}):
                if version.state.name == 'ENABLED':
                    versions.append(int(version.name.split('/')[-1]))
            if versions:
                return max(versions)
        except NotFound:
            self.log.error(f'Secret object {secret_name} not found')
        except Exception:
            self.log.exception(f'Failed to get latest secret version from secret object {secret_name}')
        return 0

    def list_secrets(self):
        """List all secret objects names"""
        payload = 'Secret objects:\n'
        for secret in self.client.list_secrets(request={'parent': self.secret_object_path}):
            payload += '  ' + secret.name.split('/')[-1] + '\n'
        self.display_success(payload.strip())

    def list_secret_versions(self, secret_name: str):
        """List all versions of a secret object.

        Args:
            secret_name (str): name of the secret object
        """
        payload = f"Versions for secret {secret_name}:\n"
        try:
            for version in self.client.list_secret_versions(request={'parent': self.get_secret_name(secret_name)}):
                payload += f'  {version.name.split("/")[-1]}, State: {version.state.name}\n'
            self.display_success(payload.strip())
        except NotFound:
            self.log.error(f'Secret object {secret_name} not found')
        except Exception:
            self.log.exception(f'Failed to list secret versions for secret object {secret_name}')

    def load_file_data_and_create_secret(self, file: str, secret_name: str, key: bytes = None, mode='r'):
        """Load data from a file and create a secret object with the data.

        Args:
            file (str): path to the file
            secret_name (str): name of the secret object
            key (bytes, optional): xor key to encrypt the data. Defaults to None.
            mode (str, optional): file mode to open the file data. Defaults to 'r'.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(file, mode) as f:
                data = f.read()
        except Exception:
            self.log.exception(f'Failed to load data from file {file} to create secret')
            return False
        if data:
            return self.create_secret(secret_name, data, key)
        self.log.error(f'Failed to load data from file {file} to create secret')
        return False

    def get_service_accounts(self):
        accounts = []
        for file in Path(f'{Path(__file__).parent}/gcp_env/').glob('*.sa'):
            accounts.append(file.name.split('.')[1])
        return accounts

    def list_service_accounts(self):
        payload = 'Service accounts:\n'
        default = self.__get__default_service_account()
        for sa in self.get_service_accounts():
            payload += '  ' + sa + ' (default)\n' if sa == default else '  ' + sa + '\n'
        self.display_success(payload.strip())

    def set_default_service_account(self, default: str):
        if default in self.get_service_accounts():
            try:
                with open(self.default_sa, 'w') as file:
                    file.write(default)
                self.display_success(f'Set default service account to {default}')
                return True
            except Exception:
                self.log.exception(f'Failed to set default service account to {default}')
        else:
            self.log.error(f'Service account {default} not found')
        return False

    def remove_service_account(self, service_account: str):
        if self.__get__default_service_account() == service_account:
            self.log.error('Cannot remove default service account')
            return False
        if service_account in self.get_service_accounts():
            try:
                remove(f'{Path(__file__).parent}/gcp_env/.{service_account}.sa')
                self.display_success(f'Removed service account {service_account}')
                return True
            except Exception:
                self.log.exception(f'Failed to remove service account {service_account}')
        else:
            self.log.error(f'Service account {service_account} not found')
        return False

    def add_service_account(self, sa_path: str):
        path = Path(sa_path)
        if path.exists():
            sa = self._load_json_service_account(path)
            if sa:
                name = sa.get('client_email', '').split('@')[0]
                return self._create_service_account_file(f'{Path(__file__).parent}/gcp_env/.{name}.sa', sa)
        else:
            self.log.error(f'File not found: {sa_path}')
        return False
