#!/bin/bash
# Quick fix for coverage database issues

echo "🔧 Fixing coverage database issues..."

# Remove all coverage files
rm -f .coverage*
rm -rf htmlcov/
rm -f coverage.xml coverage.json

echo "✅ Cleaned coverage files"

# Upgrade coverage tools to latest versions
pip install --upgrade coverage pytest-cov

echo "✅ Updated coverage tools"

# Run tests without coverage first to ensure they work
echo "🧪 Testing without coverage..."
pytest tests/component/ -v --tb=short --disable-warnings --no-cov

if [ $? -eq 0 ]; then
    echo "✅ Tests pass without coverage"

    # Now run with coverage using fresh database
    echo "📊 Running with coverage..."
    pytest tests/component/ \
        --cov=plugins.action \
        --cov=plugins.module_utils \
        --cov-report=term-missing \
        --cov-report=html:htmlcov \
        --cov-branch \
        -v --tb=short

    if [ $? -eq 0 ]; then
        echo "🎉 Coverage completed successfully!"
    else
        echo "⚠️ Coverage completed with warnings but tests passed"
    fi
else
    echo "❌ Tests failing - fix tests first"
fi
