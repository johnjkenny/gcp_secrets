from setuptools import setup


try:
    setup(
        name='gsecrets',
        version='1.0.0',
        entry_points={'console_scripts': [
            'gsecret = gcp_secrets.cli:secret_parent',
            'gsecret-init = gcp_secrets.cli:secret_init',
            'gsecret-create = gcp_secrets.cli:secret_create',
            'gsecret-get = gcp_secrets.cli:secret_get',
            'gsecret-delete = gcp_secrets.cli:secret_delete',
            'gsecret-sa = gcp_secrets.cli:secret_sa',
        ]},
    )
    exit(0)
except Exception as error:
    print(f'Failed to setup package: {error}')
    exit(1)
