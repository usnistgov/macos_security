# How to setup project to run on your local machine

## Requirements

- Python >= 3.12.1
  - Recommended: [Macadmins python](https://github.com/macadmins/python)
- Ruby >= 3.4.4

## Python Instructions

Follow the below instructions to setup the environment to work with the project.

### Create virtual environment

```bash
python3 -m venv .venv

source .venv/bin/activate
```

### Update and install tools

```bash
python3 -m pip install --upgrade pip setuptools wheel

python3 -m pip install --upgrade -r requirements.txt
```

## Ruby instructions

### Setup bundle configuration file

```bash
bundle config path mscp_gems
bundle config bin mscp_gems/bin
```

### Install ruby tools

```bash
bundle install
bundle binstubs --all
```
