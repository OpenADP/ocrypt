#!/bin/bash

# Ocrypt Publishing Script
# This script helps prepare the ocrypt module for publishing

set -e

echo "🚀 Ocrypt Publishing Helper"
echo "=========================="

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    echo "❌ Error: No go.mod found. Run this script from the ocrypt directory."
    exit 1
fi

# Check if this is the ocrypt module
if ! grep -q "module github.com/openadp/ocrypt" go.mod; then
    echo "❌ Error: This doesn't appear to be the ocrypt module."
    exit 1
fi

echo "✅ Found ocrypt module"

# Run tests
echo "🧪 Running tests..."
if go test ./...; then
    echo "✅ All tests pass"
else
    echo "❌ Tests failed. Fix tests before publishing."
    exit 1
fi

# Build examples
echo "🔨 Building examples..."
if go build ./examples/basic; then
    echo "✅ Examples build successfully"
    rm -f basic # Clean up binaries
else
    echo "❌ Examples failed to build"
    exit 1
fi

# Check formatting
echo "📝 Checking code formatting..."
if [ -n "$(gofmt -l .)" ]; then
    echo "❌ Code is not properly formatted. Run 'go fmt ./...' first."
    gofmt -l .
    exit 1
else
    echo "✅ Code is properly formatted"
fi

# Verify module dependencies
echo "📦 Verifying dependencies..."
go mod tidy
go mod verify
echo "✅ Dependencies verified"

echo ""
echo "🎉 Ready for publishing!"
echo ""
echo "Next steps:"
echo "1. Create a new repository: github.com/openadp/ocrypt"
echo "2. Copy this entire directory to the new repository"
echo "3. Commit and push:"
echo "   git add ."
echo "   git commit -m 'Initial release'"
echo "   git tag v1.0.0"
echo "   git push origin main"
echo "   git push origin v1.0.0"
echo ""
echo "4. The module will be available at:"
echo "   go get github.com/openadp/ocrypt@latest"
echo ""
echo "5. Documentation will be automatically generated at:"
echo "   https://pkg.go.dev/github.com/openadp/ocrypt" 