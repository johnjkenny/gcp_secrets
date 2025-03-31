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
        """Create a GCP Secret Manager object to interact with the GCP Secret Manager API

        Args:
            service_account (str, optional): service account name to use. Defaults to 'default'.
            project_id (str, optional): GCP project ID to use. Defaults to '' and will be set with service account info
        """
        self.log = get_logger('gcp-secrets')
        self.service_account = service_account
        self.project_id = project_id
        self.__client: SecretManagerServiceClient | None = None
        self.__cipher: Cipher | None = None

    @property
    def default_sa(self) -> str:
        """Get the default service account file path

        Returns:
            str: default service account file path
        """
        return f'{Path(__file__).parent}/gcp_env/default_sa'

    @property
    def sa_file(self) -> str:
        """Get the service account file path. Looks up default service account if 'default' is set

        Returns:
            str: service account file path
        """
        if self.service_account == 'default':
            self.service_account = self.__get_default_service_account()
        return f'{Path(__file__).parent}/gcp_env/.{self.service_account}.sa'

    @property
    def secret_object_path(self) -> str:
        """Get the full path of the secret object

        Returns:
            str: full path of the secret object- projects/{project_id}
        """
        return f'projects/{self.project_id}'

    @property
    def cipher(self) -> Cipher:
        """Get the cipher object for encryption/decryption

        Returns:
            Cipher: cipher object
        """
        if self.__cipher is None:
            self.__cipher = Cipher(self.log)
        return self.__cipher

    @property
    def creds(self) -> service_account.Credentials | None:
        """Get the service account credentials object. Sets the project ID if not set

        Returns:
            service_account.Credentials | None: service account credentials object or None on failure
        """
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
    def client(self) -> SecretManagerServiceClient | None:
        """Get the secret manager client object

        Returns:
            SecretManagerServiceClient | None: secret manager client object or None on failure
        """
        if self.__client is None:
            try:
                self.__client = SecretManagerServiceClient(credentials=self.creds)
            except Exception:
                self.log.exception('Failed to load secret client')
        return self.__client

    @staticmethod
    def display_success(msg: str):
        """Display a success message on console (green)

        Args:
            msg (str): message to display to console
        """
        Color().print_message(msg, 'green')

    @staticmethod
    def display_failed(msg: str):
        """Display a failed message on console (red)

        Args:
            msg (str): message to display to console
        """
        Color().print_message(msg, 'red')

    def _prompt_for_passwd(self, verify: bool = False) -> str:
        """Prompt for a password on console without echoing

        Args:
            verify (bool, optional): True if password needs to be verified. Defaults to False.

        Returns:
            str: password provided
        """
        passwd = getpass('Enter password: ')
        if not passwd:
            self.log.error('Password cannot be empty')
            return self._prompt_for_passwd(verify)
        if verify:
            passwd_verify = getpass('Verify password: ')
            if passwd != passwd_verify:
                self.log.error('Passwords do not match')
                return self._prompt_for_passwd(verify)
        return passwd

    def _create_service_account_file(self, sa_file: str, sa_data: dict) -> bool:
        """Create a service account file and encrypt it with the cipher key.

        Args:
            sa_file (str): path to the service account file
            sa_data (dict): service account data

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(sa_file, 'wb') as file:
                file.write(self.cipher.encrypt(dumps(sa_data), self.cipher.load_key()))
            return True
        except Exception:
            self.log.exception('Failed to create service account file')
        return False

    def _load_json_service_account(self, sa_path: str) -> dict:
        """Load a service account json file to a dictionary

        Args:
            sa_path (str): path to the service account json file

        Returns:
            dict: service account data
        """
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

    def __create_secret_object(self, secret_name: str) -> bool:
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

    def __get_default_service_account(self) -> str:
        """Get the default service account name

        Returns:
            str: default service account name or empty string if failed
        """
        try:
            with open(self.default_sa, 'r') as file:
                return file.read().strip()
        except Exception:
            self.log.exception('Failed to load default service account')
        return ''

    def add_secret_version(self, secret_name: str, payload: bytes) -> bool:
        """Add a secret version to an existing secret object.

        Args:
            secret_name (str): name of the secret object
            payload (object): data to store in the secret object

        Returns:
            bool: True if successful, False otherwise
        """
        if self.client:
            try:
                request = {'parent': self.get_secret_name(secret_name), 'payload': {'data': payload}}
                self.client.add_secret_version(request=request)
                self.log.info(f'Added secret version to secret object {secret_name}')
                return True
            except Exception:
                self.log.exception(f'Failed to add secret version to secret object {secret_name}')
        return False

    def create_secret(self, secret_name: str, payload: bytes, passwd: bool = False) -> bool:
        """Create a secret object and add a secret version to it. If the secret object already exists, only add a secret
        version to it making it the latest secret version.

        Args:
            secret_name (str): name of the secret object
            payload (bytes): data to store in the secret object
            passwd (bool, optional): True if password prompt is required to encrypt payload. Defaults to False.

        Returns:
            bool: True if successful, False otherwise
        """
        if passwd:
            payload = self.cipher.passwd_xor(payload, self._prompt_for_passwd(True))
        return self.__create_secret_object(secret_name) and self.add_secret_version(secret_name, payload)

    def create_secret_from_file(self, secret_name: str, file_path: str, passwd: bool = False) -> bool:
        """Create a secret object and add a secret version to it from a file. If the secret object already exists, only
        add a secret version to it making it the latest secret

        Args:
            secret_name (str): name of the secret object
            file_path (str): path to the file to store in the secret object
            passwd (bool, optional): True if password prompt is required to encrypt payload. Defaults to False.

        Returns:
            bool: True if successful, False otherwise
        """
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

    def get_secret(self, secret_name: str, passwd: bool = False, version: str = 'latest',
                   display: bool = False) -> bytes:
        """Pull secret version data from a secret object.

        Args:
            secret_name (str): name of the secret object
            passwd (bool, optional): True if password prompt is required to decrypt payload. Defaults to False.
            version (str, optional): secret version to pull. Defaults to 'latest'.
            display (bool, optional): True if secret data needs to be displayed on console. Defaults to False.

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
                data = self.cipher.passwd_xor(rsp.payload.data, self._prompt_for_passwd(False))
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

    def get_secret_to_file(self, secret_name: str, file_path: str, passwd: bool = False,
                           version: str = 'latest') -> bool:
        """Pull secret version data from a secret object and write it to a file.

        Args:
            secret_name (str): name of the secret object
            file_path (str): path to the file to write the secret data
            passwd (bool, optional): True if password prompt is required to decrypt payload. Defaults to False.
            version (str, optional): version to pull. Defaults to 'latest'.

        Returns:
            bool: True if successful, False otherwise
        """
        data = self.get_secret(secret_name, passwd, version)
        if data:
            try:
                with open(file_path, 'wb') as file:
                    file.write(data)
                return True
            except Exception:
                self.log.exception(f'Failed to write secret data to file {file_path}')
        return False

    def delete_secret(self, secret_name: str) -> bool:
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

    def delete_secret_version(self, secret_name: str, version: str) -> bool:
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

    def disable_secret_version(self, secret_name: str, version: int) -> bool:
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

    def enable_secret_version(self, secret_name: str, version: str) -> bool:
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
            except FailedPrecondition as error:
                if 'SecretVersion.state is DESTROYED' in error.message:
                    self.log.error(f'Can not enable. Version {version} is destroyed in secret object {secret_name}')
                else:
                    self.log.error(error.message)
            except Exception:
                self.log.exception(f'Failed to enable secret version {version} from secret object {secret_name}')
        return False

    def secret_exists(self, secret_name: str) -> bool:
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

    def get_latest_secret_version(self, secret_name: str) -> int:
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

    def list_secrets(self) -> bool:
        """List all secret objects.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            payload = 'Secret objects:\n'
            for secret in self.client.list_secrets(request={'parent': self.secret_object_path}):
                payload += '  ' + secret.name.split('/')[-1] + '\n'
            self.display_success(payload.strip())
            return True
        except Exception:
            self.log.exception('Failed to list secret objects')
        return False

    def list_secret_versions(self, secret_name: str) -> bool:
        """List all versions of a secret object.

        Args:
            secret_name (str): name of the secret object

        Returns:
            bool: True if successful, False otherwise
        """
        payload = f"Versions for secret {secret_name}:\n"
        try:
            for version in self.client.list_secret_versions(request={'parent': self.get_secret_name(secret_name)}):
                payload += f'  {version.name.split("/")[-1]}, State: {version.state.name}\n'
            self.display_success(payload.strip())
            return True
        except NotFound:
            self.log.error(f'Secret object {secret_name} not found')
        except Exception:
            self.log.exception(f'Failed to list secret versions for secret object {secret_name}')
        return False

    def get_service_accounts(self) -> list:
        """Get a list of service accounts

        Returns:
            list: list of service accounts
        """
        accounts = []
        for file in Path(f'{Path(__file__).parent}/gcp_env/').glob('*.sa'):
            accounts.append(file.name.split('.')[1])
        return accounts

    def list_service_accounts(self) -> None:
        """List all service accounts"""
        payload = 'Service accounts:\n'
        default = self.__get_default_service_account()
        for sa in self.get_service_accounts():
            payload += '  ' + sa + ' (default)\n' if sa == default else '  ' + sa + '\n'
        self.display_success(payload.strip())

    def set_default_service_account(self, default: str) -> bool:
        """Set the default service account

        Args:
            default (str): service account name

        Returns:
            bool: True if successful, False otherwise
        """
        if default in self.get_service_accounts():
            try:
                with open(self.default_sa, 'w') as file:
                    file.write(default)
                self.display_success(f'Set default service account to {default}')
                self.list_service_accounts()
                return True
            except Exception:
                self.log.exception(f'Failed to set default service account to {default}')
        else:
            self.log.error(f'Service account {default} not found')
        return False

    def remove_service_account(self, service_account: str) -> bool:
        """Remove a service account. Cannot remove the default service account.

        Args:
            service_account (str): service account name

        Returns:
            bool: True if successful, False otherwise
        """
        if self.__get_default_service_account() == service_account:
            self.log.error('Cannot remove default service account')
            return False
        if service_account in self.get_service_accounts():
            try:
                remove(f'{Path(__file__).parent}/gcp_env/.{service_account}.sa')
                self.display_success(f'Removed service account {service_account}')
                self.list_service_accounts()
                return True
            except Exception:
                self.log.exception(f'Failed to remove service account {service_account}')
        else:
            self.log.error(f'Service account {service_account} not found')
        return False

    def add_service_account(self, sa_path: str) -> bool:
        """Add a service account

        Args:
            sa_path (str): path to the service account json file

        Returns:
            bool: True if successful, False otherwise
        """
        path = Path(sa_path)
        if path.exists():
            sa = self._load_json_service_account(path)
            if sa:
                name = sa.get('client_email', '').split('@')[0]
                if self._create_service_account_file(f'{Path(__file__).parent}/gcp_env/.{name}.sa', sa):
                    self.display_success(f'Added service account {name}')
                    self.list_service_accounts()
                    return True
        else:
            self.log.error(f'File not found: {sa_path}')
        return False
