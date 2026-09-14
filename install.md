# How to setup project to run on your local machine

## Requirements

- Python >= 3.12.1

## Python Instructions

Follow the below instructions to setup the environment to work with the project.

### Create virtual environment

```bash
python3 -m venv .venv

source .venv/bin/activate
```

### Update pip and install python requirements

```bash
python3 -m pip install --upgrade pip

python3 -m pip install --upgrade -r requirements.txt
```

You can now run the `./mscp.py` CLI to get started.

## PDF generation (typst)

Guidance PDFs are rendered with [typst](https://typst.app) (no Ruby, no LaTeX).
It ships as the [`typst`](https://pypi.org/project/typst/) Python package — a
regular project dependency — so the standard install above (or `uv sync`) is all
you need; there is no separate tool to install. HTML and Markdown guidance are
generated in pure Python.

## Install as python module for development (optional)

Installing mSCP as a python module will allow developers to leverage the API to work with the MSCP data.

```bash
python3 -m pip install git+https://github.com/usnistgov/macos_security@main
```

You can now use the MSCP modules by way of `import mscp` in your own python tool.
