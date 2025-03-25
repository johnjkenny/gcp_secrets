# GCP-Secrets

This repository contains the code to demonstrate how to use Google Cloud Platform (GCP) Secrets Manager to store and
retrieve secrets. You can use it in your CI/CD pipeline to store secrets like API keys, passwords, etc. securely.
You can also use it as a personal password manager. It has the option to use a password to encrypt and decrypt the
secret data so incase the GCP service account key is compromised the secret data is still secure. The service account
keys are stored in the `gcp_secrets/gcp_env` directory and encrypted with a generated cipher key.

The tool has the following features:
- Initialize the GCP Secret Manager
- Create a secret or a new version of a secret
- Get a secret or a version of a secret
- Delete a secret or a version of a secret
- List all secrets or versions of a secret
- Add a service account
- Remove a service account
- Set default service account
- Specify the service account to use
- Specify the project ID to use

## Prerequisites

- GCP project access
- Secret Manager API enabled in project
- Create service account that has `Secret Manager Admin` permissions
- Download service account key in JSON format


## Installation
The installation process will walk you through creating a virtual environment, installing the required packages, and
installing the console scripts then initializing the GCP Secret Manager by providing the service account key that
will be used to access the GCP Secret Manager.


1. Create virtual Environment
```bash
python3 -m venv venv
```

2. Activate virtual Environment
```bash
source venv/bin/activate
```

3. Install requirements
```bash
pip install -r requirements.txt
```

4. Install console scripts
```bash
pip install -e .
```

5. Initialize the GCP Secret Manager
```bash
gsecret -I -h    
usage: gsecret [-h] -sa SERVICEACCOUNT [-d] [-F]

GCP Secret Initialization

options:
  -h, --help            show this help message and exit

  -sa SERVICEACCOUNT, --serviceAccount SERVICEACCOUNT
                        Service account path (full path to json file)

  -d, --default         Set as default service account

  -F, --force           Force action


gsecret -I -sa /home/myUser/sa.json
```

## Usage

### Parent Commands:
```bash
gsecret -h
usage: gsecret [-h] [-I ...] [-s ...] [-c ...] [-g ...] [-d ...]

GCP Secret Commands

options:
  -h, --help            show this help message and exit

  -I ..., --init ...    Initialize commands (gsecret-init)

  -s ..., --serviceAccounts ...
                        Service account commands (gsecret-sa)

  -c ..., --create ...  Create a secret object (gsecret-create)

  -g ..., --get ...     Get secret data (gsecret-get)

  -d ..., --delete ...  Delete a secret object (gsecret-delete)
```

### Create a secret

```bash
# command options:
gsecret -c -h            
usage: gsecret [-h] [-sa SERVICEACCOUNT] -n NAME [-ff FROMFILE] [-s SECRET] [-p] [-pi PROJECTID]

GCP Secret Create

options:
  -h, --help            show this help message and exit

  -sa SERVICEACCOUNT, --serviceAccount SERVICEACCOUNT
                        Service account name. Default: default

  -n NAME, --name NAME  Secret name

  -ff FROMFILE, --fromFile FROMFILE
                        Create secret from file (full path to file)

  -s SECRET, --secret SECRET
                        Secret data. Provide secret data as argument string

  -p, --password        Password to encrypt secret data

  -pi PROJECTID, --projectID PROJECTID
                        Project ID. Default: Service account project

# From string
gsecret -c -n test01 -s 'mySecretData321'
[2025-03-24 20:52:50,928][INFO][secrets,112]: Created secret object test01
[2025-03-24 20:52:51,850][INFO][secrets,143]: Added secret version to secret object test01

# From file
echo '321secretMy' >> secret.txt
gsecret -c -n test02 -ff ./secret.txt 
[2025-03-24 21:10:54,850][INFO][secrets,112]: Created secret object test02
[2025-03-24 21:10:55,873][INFO][secrets,143]: Added secret version to secret object test02

# Create a new version of the secret
gsecret -c -n test02 -s 'newVersionSecret123'
[2025-03-24 21:15:34,713][INFO][secrets,143]: Added secret version to secret object test02

# Create a secret with password
gsecret -c -n test03 -s 'verySecret' -p
Enter password: 
Verify password:
[2025-03-24 21:38:54,544][INFO][secrets,112]: Created secret object test03
[2025-03-24 21:39:01,609][INFO][secrets,143]: Added secret version to secret object test03
```


### Get a secret

```bash
# command options:
gsecret -g -h
usage: gsecret [-h] [-sa SERVICEACCOUNT] [-t TOFILE] [-n NAME] [-l] [-v VERSION] [-p]
               [-pi PROJECTID]

GCP Secret Get

options:
  -h, --help            show this help message and exit

  -sa SERVICEACCOUNT, --serviceAccount SERVICEACCOUNT
                        Service account name. Default: default

  -t TOFILE, --toFile TOFILE
                        Store secret to file (full path to file)

  -n NAME, --name NAME  Secret name

  -l, --list            List all secrets

  -v VERSION, --version VERSION
                        Secret version. Default: latest

  -p, --password        Password to decrypt secret data

  -pi PROJECTID, --projectID PROJECTID
                        Project ID. Default: Service account project


# List all secret names
gsecret -g -l                                
  test01
  test02

# List versions of a secret
gsecret -g -l -n test02
Versions for secret test02:
  2, State: ENABLED
  1, State: ENABLED

# Display to  console
gsecret -g -n test01
mySecretData321

gsecret -g -n test02                 
321secretMy

# Get and save to a file
gsecret -g -n test01 -t ./my_secret
cat my_secret 
mySecretData321

# Specify the secret version to get
gsecret -g -n test02 -v 1
321secretMy

gsecret -g -n test02 -v 2
newVersionSecret123

# Get a secret with password
gsecret -g -n test03 -p             
Enter password: 
verySecret

# Save secret to file with password:
gsecret -g -n test03 -t ./test03.txt -p
Enter password:

cat test03.txt 
verySecret

# Getting secret with password without providing password
gsecret -g -n test03
[2025-03-24 21:46:32,177][ERROR][secrets,207]: Failed to decrypt secret data
```


### Delete a secret
```bash
# command options:
gsecret -d -h                       
usage: gsecret [-h] [-sa SERVICEACCOUNT] -n NAME [-v VERSION] [-d] [-e] [-pi PROJECTID]

GCP Secret Delete

options:
  -h, --help            show this help message and exit

  -sa SERVICEACCOUNT, --serviceAccount SERVICEACCOUNT
                        Service account name. Default: default

  -n NAME, --name NAME  Secret name

  -v VERSION, --version VERSION
                        Secret version to delete. Will delete all secret versions if not specified.
                        Default: all

  -d, --disable         Disable the secret version instead of deleting it

  -e, --enable          Enable the secret version

  -pi PROJECTID, --projectID PROJECTID
                        Project ID. Default: Service account project


# Delete a specific version of a secret
gsecret -d -n test02 -v 1
[2025-03-24 21:29:45,365][INFO][secrets,253]: Deleted secret version 1 from secret object test02

gsecret -g -l -n test02
Versions for secret test02:
  2, State: ENABLED
  1, State: DESTROYED

gsecret -d -n test02 -v 2
[2025-03-24 21:31:04,315][INFO][secrets,253]: Deleted secret version 2 from secret object test02

gsecret -g -l -n test02  
Versions for secret test02:
  2, State: DESTROYED
  1, State: DESTROYED

gsecret -g -n test02   
[2025-03-24 21:31:18,091][ERROR][secrets,195]: Secret version latest is not enabled in secret object test02

gsecret -g -n test02 -v 1
[2025-03-24 21:31:34,081][ERROR][secrets,195]: Secret version 1 is not enabled in secret object test02

# Completely delete a secret
gsecret -d -n test02
[2025-03-24 21:32:32,687][INFO][secrets,231]: Deleted secret object test02

gsecret -g -l -n test02
[2025-03-24 21:36:14,922][ERROR][secrets,368]: Secret object test02 not found

# Disable a secret version instead of deleting it
gsecret -d -n test03 -d -v 1
[2025-03-25 14:47:13,626][INFO][secrets,411]: Disabled secret version 1 from secret object test03

gsecret -g -l -n test03     
Versions for secret test03:
  1, State: DISABLED

# Enable a secret version
gsecret -d -n test03 -e -v 1
[2025-03-25 14:47:31,990][INFO][secrets,433]: Enabled secret version 1 from secret object test03

gsecret -g -l -n test03     
Versions for secret test03:
  1, State: ENABLED
```

### Service Account Commands
```bash
# command options:
gsecret -s -h            
usage: gsecret [-h] [-a ADD] [-l] [-d DEFAULT] [-r REMOVE]

GCP Secret Service Account

options:
  -h, --help            show this help message and exit

  -a ADD, --add ADD     Service account path (full path to json file)

  -l, --list            List all service accounts

  -d DEFAULT, --default DEFAULT
                        Set default service account by name

  -R REMOVE, --remove REMOVE
                        Remove service account by name


# List all service accounts
gsecret -s -l
Service accounts:
  test-sa01 (default)

# Add a new service account
gsecret -s -a /home/myUser/sa2.json
Added service account test-sa02
Service accounts:
  test-sa02
  test-sa01 (default)

# Set default service account
gsecret -s -d test-sa02
Set default service account to test-sa02
Service accounts:
  test-sa02 (default)
  test-sa01

# Remove service account
gsecret -s -R test-sa02
Removed service account test-sa02
Service accounts:
  test-sa01 (default)
```
