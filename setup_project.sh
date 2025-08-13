#!/usr/bin/env bash

set -e

# --- Dry run flag ---
DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "💡 Running in DRY-RUN mode — no commands will be executed."
fi

run_cmd() {
    echo "+ $*"
    if [ "$DRY_RUN" = false ]; then
        eval "$@"
    fi
}

echo "=== Project Initialization Script ==="

# --- Requirements check ---
echo "Checking for Python 3.12.1 or higher..."
if ! command -v python3 >/dev/null 2>&1; then
    if [ "$DRY_RUN" = false ]; then
        echo "❌ Python 3 is not installed. Please install Python 3.12.1 or higher."
        exit 1
    else
        echo "⚠️ (dry-run) Python 3 not found — skipping check."
    fi
else
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    if [[ "$(printf '%s\n' "3.12.1" "$PYTHON_VERSION" | sort -V | head -n1)" != "3.12.1" ]]; then
        if [ "$DRY_RUN" = false ]; then
            echo "❌ Python version $PYTHON_VERSION is too old. Please upgrade to 3.12.1 or newer."
            exit 1
        else
            echo "⚠️ (dry-run) Python version $PYTHON_VERSION too old — skipping check."
        fi
    else
        echo "✅ Python $PYTHON_VERSION detected."
    fi
fi

echo "Checking for Ruby 3.4.4 or higher..."
if ! command -v ruby >/dev/null 2>&1; then
    if [ "$DRY_RUN" = false ]; then
        echo "❌ Ruby is not installed. Please install Ruby 3.4.4 or higher."
        exit 1
    else
        echo "⚠️ (dry-run) Ruby not found — skipping check."
    fi
else
    RUBY_VERSION=$(ruby -v | awk '{print $2}')
    if [[ "$(printf '%s\n' "3.4.4" "$RUBY_VERSION" | sort -V | head -n1)" != "3.4.4" ]]; then
        if [ "$DRY_RUN" = false ]; then
            echo "❌ Ruby version $RUBY_VERSION is too old. Please upgrade to 3.4.4 or newer."
            exit 1
        else
            echo "⚠️ (dry-run) Ruby version $RUBY_VERSION too old — skipping check."
        fi
    else
        echo "✅ Ruby $RUBY_VERSION detected."
    fi
fi

# --- Python setup ---
echo ""
echo "=== Setting up Python environment ==="
echo "Creating Python virtual environment..."
run_cmd python3 -m venv .venv
run_cmd "source .venv/bin/activate"

echo "Upgrading pip, setuptools, and wheel..."
run_cmd python3 -m pip install --upgrade pip setuptools wheel

if [ -f "requirements.txt" ]; then
    echo "Installing Python requirements..."
    run_cmd python3 -m pip install --upgrade -r requirements.txt
else
    echo "⚠️ requirements.txt not found. Skipping Python dependency install."
fi

# --- Ruby setup ---
echo ""
echo "=== Setting up Ruby environment ==="
echo "Configuring Ruby environment..."
run_cmd bundle config path mscp_gems
run_cmd bundle config bin mscp_gems/bin

echo "Installing Ruby gems..."
run_cmd bundle install

echo "Generating binstubs..."
run_cmd bundle binstubs --all

echo ""
echo "✅ Project setup complete."
if [ "$DRY_RUN" = true ]; then
    echo "💡 This was only a dry run — no changes were made."
fi