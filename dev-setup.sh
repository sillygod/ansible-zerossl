#!/bin/bash
# Development Environment Setup for Ansible ZeroSSL Plugin

set -e

echo "🚀 Setting up Ansible ZeroSSL Plugin development environment..."

# Check Python version
echo "📋 Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.12"

if [[ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]]; then
    echo "❌ Python 3.12+ required. Found: $python_version"
    echo "Please install Python 3.12 or higher"
    exit 1
fi
echo "✅ Python version check passed: $python_version"

# Create virtual environment
echo "🐍 Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "ℹ️ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Install development dependencies
echo "🛠️ Installing development dependencies..."
pip install -e .[dev]

# Verify Ansible installation
echo "🔍 Verifying Ansible installation..."
ansible --version
echo "✅ Ansible verification complete"

# Set up pre-commit hooks (if available)
if command -v pre-commit &> /dev/null; then
    echo "🪝 Setting up pre-commit hooks..."
    pre-commit install
    echo "✅ Pre-commit hooks installed"
else
    echo "ℹ️ pre-commit not available, skipping hook setup"
fi

# Create vault password file template
if [ ! -f ".vault_pass" ]; then
    echo "🔐 Creating vault password file template..."
    echo "# Add your vault password here (DO NOT COMMIT)" > .vault_pass
    chmod 600 .vault_pass
    echo "✅ Vault password file template created"
fi

# Verify project structure
echo "📁 Verifying project structure..."
required_dirs=(
    "action_plugins"
    "module_utils/zerossl"
    "tests/unit"
    "tests/integration"
    "tests/fixtures"
)

for dir in "${required_dirs[@]}"; do
    if [ -d "$dir" ]; then
        echo "✅ $dir"
    else
        echo "❌ Missing: $dir"
    fi
done

# Run basic tests to verify setup
echo "🧪 Running basic setup verification..."
python3 -c "import ansible; print(f'Ansible version: {ansible.__version__}')"

# Display next steps
echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "Next steps:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Add your ZeroSSL API key to inventory or vault"
echo "3. Run tests: make test"
echo "4. Start developing: implement T005-T038"
echo ""
echo "Useful commands:"
echo "  make help          - Show all available commands"
echo "  make test          - Run all tests"
echo "  make test-unit     - Run unit tests only"
echo "  make lint          - Run code linting"
echo "  make format        - Format code"
echo ""
echo "Happy coding! 🚀"
