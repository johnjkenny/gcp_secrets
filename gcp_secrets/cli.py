from argparse import REMAINDER

from gcp_secrets.arg_parser import ArgParser


def parse_parent_args(args: dict):
    if args.get('init'):
        return secret_init(args['init'])
    if args.get('create'):
        return secret_create(args['create'])
    if args.get('get'):
        return secret_get(args['get'])
    if args.get('delete'):
        return secret_delete(args['delete'])
    if args.get('serviceAccounts'):
        return secret_service_account(args['serviceAccounts'])
    return True


def secret_parent():
    args = ArgParser('GCP Secret Commands', None, {
        'init': {
            'short': 'I',
            'help': 'Initialize commands (gsecret-init)',
            'nargs': REMAINDER
        },
        'serviceAccounts': {
            'short': 's',
            'help': 'Service account commands (gsecret-sa)',
            'nargs': REMAINDER
        },
        'create': {
            'short': 'c',
            'help': 'Create a secret object (gsecret-create)',
            'nargs': REMAINDER
        },
        'get': {
            'short': 'g',
            'help': 'Get secret data (gsecret-get)',
            'nargs': REMAINDER
        },
        'delete': {
            'short': 'd',
            'help': 'Delete a secret object (gsecret-delete)',
            'nargs': REMAINDER
        }
    }).set_arguments()
    if not parse_parent_args(args):
        exit(1)
    exit(0)


def parse_init_args(args: dict):
    from gcp_secrets.init import Init
    if args.get('serviceAccount'):
        return Init(args['serviceAccount'], args['default'], args['force'])._run()
    return True


def secret_init(parent_args: list = None):
    args = ArgParser('GCP Secret Initialization', parent_args, {
        'serviceAccount': {
            'short': 'sa',
            'help': 'Service account path (full path to json file)',
            'required': True,
        },
        'default': {
            'short': 'd',
            'help': 'Set as default service account',
            'action': 'store_true',
        },
        'force': {
            'short': 'F',
            'help': 'Force action',
            'action': 'store_true',
        }
    }).set_arguments()
    if not parse_init_args(args):
        exit(1)
    exit(0)


def parse_create_args(args: dict):
    from gcp_secrets.secrets import GCPSecrets
    if args.get('fromFile'):
        return GCPSecrets(args['serviceAccount'], args['projectID']).create_secret_from_file(
            args['name'], args['fromFile'], args['password'])
    if args.get('secret'):
        return GCPSecrets(args['serviceAccount'], args['projectID']).create_secret(
            args['name'], args['secret'].encode(), args['password'])
    return True


def secret_create(parent_args: list = None):
    args = ArgParser('GCP Secret Create', parent_args, {
        'serviceAccount': {
            'short': 'sa',
            'help': 'Service account name. Default: default',
            'default': 'default',
        },
        'name': {
            'short': 'n',
            'help': 'Secret name',
            'required': True,
        },
        'fromFile': {
            'short': 'ff',
            'help': 'Create secret from file (full path to file)',
        },
        'secret': {
            'short': 's',
            'help': 'Secret data. Provide secret data as argument string',
            'type': str,
        },
        'password': {
            'short': 'p',
            'help': 'Password to encrypt secret data',
            'action': 'store_true',
        },
        'projectID': {
            'short': 'pi',
            'help': 'Project ID. Default: Service account project',
            'default': '',
        }
    }).set_arguments()
    if not parse_create_args(args):
        exit(1)
    exit(0)


def parse_get_args(args: dict):
    from gcp_secrets.secrets import GCPSecrets
    if args.get('list'):
        if args.get('name'):
            return GCPSecrets(args['serviceAccount'], args['projectID']).list_secret_versions(args['name'])
        return GCPSecrets(args['serviceAccount'], args['projectID']).list_secrets()
    elif args.get('name'):
        if args.get('toFile'):
            GCPSecrets(args['serviceAccount'], args['projectID']).get_secret_to_file(
                args['name'], args['toFile'], args['password'], args['version'])
        else:
            GCPSecrets(args['serviceAccount'], args['projectID']).get_secret(
                args['name'], args['password'], args['version'], True)
    return True


def secret_get(parent_args: list = None):
    args = ArgParser('GCP Secret Get', parent_args, {
        'serviceAccount': {
            'short': 'sa',
            'help': 'Service account name. Default: default',
            'default': 'default',
        },
        'toFile': {
            'short': 't',
            'help': 'Store secret to file (full path to file)',
        },
        'name': {
            'short': 'n',
            'help': 'Secret name',
        },
        'list': {
            'short': 'l',
            'help': 'List all secrets',
            'action': 'store_true',
        },
        'version': {
            'short': 'v',
            'help': 'Secret version. Default: latest',
            'default': 'latest',
        },
        'password': {
            'short': 'p',
            'help': 'Password to decrypt secret data',
            'action': 'store_true',
        },
        'projectID': {
            'short': 'pi',
            'help': 'Project ID. Default: Service account project',
            'default': '',
        }
    }).set_arguments()
    if not parse_get_args(args):
        exit(1)
    exit(0)


def parse_delete_args(args: dict):
    from gcp_secrets.secrets import GCPSecrets
    if args.get('name'):
        if args['version'] == 'all':
            return GCPSecrets(args['serviceAccount'], args['projectID']).delete_secret(args['name'])
        if args.get('disable'):
            return GCPSecrets(args['serviceAccount'], args['projectID']).disable_secret_version(
                args['name'], args['version'])
        if args.get('enable'):
            return GCPSecrets(args['serviceAccount'], args['projectID']).enable_secret_version(
                args['name'], args['version'])
        return GCPSecrets(args['serviceAccount'], args['projectID']).delete_secret_version(
            args['name'], args['version'])
    return True


def secret_delete(parent_args: list = None):
    args = ArgParser('GCP Secret Delete', parent_args, {
        'serviceAccount': {
            'short': 'sa',
            'help': 'Service account name. Default: default',
            'default': 'default',
        },
        'name': {
            'short': 'n',
            'help': 'Secret name',
            'required': True,
        },
        'version': {
            'short': 'v',
            'help': 'Secret version to delete. Will delete all secret versions if not specified. Default: all',
            'default': 'all',
        },
        'disable': {
            'short': 'd',
            'help': 'Disable the secret version instead of deleting it',
            'action': 'store_true',
        },
        'enable': {
            'short': 'e',
            'help': 'Enable the secret version',
            'action': 'store_true',
        },
        'projectID': {
            'short': 'pi',
            'help': 'Project ID. Default: Service account project',
            'default': '',
        }
    }).set_arguments()
    if not parse_delete_args(args):
        exit(1)
    exit(0)


def parse_service_account_args(args: dict):
    from gcp_secrets.secrets import GCPSecrets
    if args.get('list'):
        GCPSecrets().list_service_accounts()
    if args.get('default'):
        return GCPSecrets().set_default_service_account(args['default'])
    if args.get('remove'):
        return GCPSecrets().remove_service_account(args['remove'])
    if args.get('add'):
        return GCPSecrets().add_service_account(args['add'])
    return True


def secret_service_account(parent_args: list = None):
    args = ArgParser('GCP Secret Service Account', parent_args, {
        'add': {
            'short': 'a',
            'help': 'Service account path (full path to json file)',
        },
        'list': {
            'short': 'l',
            'help': 'List all service accounts',
            'action': 'store_true',
        },
        'default': {
            'short': 'd',
            'help': 'Set default service account by name',
        },
        'remove': {
            'short': 'R',
            'help': 'Remove service account by name',
        },
    }).set_arguments()
    if not parse_service_account_args(args):
        exit(1)
    exit(0)
