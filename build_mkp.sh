#!/bin/bash
# Build script for PKI Monitor Checkmk plugin
# Creates an MKP (Checkmk Extension Package) file

set -e

PLUGIN_NAME="pki_monitor"
VERSION="1.0.0"
BUILD_DIR="build"
OUTPUT_FILE="${PLUGIN_NAME}-${VERSION}.mkp"

echo "Building ${PLUGIN_NAME} version ${VERSION}..."

# Clean previous build
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Create the package structure
echo "Creating package structure..."

# Copy agent_based plugins
mkdir -p "${BUILD_DIR}/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/agent_based"
cp local/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/agent_based/*.py \
   "${BUILD_DIR}/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/agent_based/"

# Copy rulesets
mkdir -p "${BUILD_DIR}/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/rulesets"
cp local/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/rulesets/*.py \
   "${BUILD_DIR}/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/rulesets/"

# Copy graphing
mkdir -p "${BUILD_DIR}/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/graphing"
cp local/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/graphing/*.py \
   "${BUILD_DIR}/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/graphing/"

# Copy Windows agent plugins
mkdir -p "${BUILD_DIR}/agents/windows/plugins"
cp local/share/check_mk/agents/windows/plugins/*.ps1 \
   "${BUILD_DIR}/agents/windows/plugins/"

# Create package info
cat > "${BUILD_DIR}/info" << EOF
{'author': 'PKI Monitor Plugin',
 'description': 'Monitor Microsoft Active Directory Certificate Services (ADCS) and track certificate expiration across your PKI infrastructure.',
 'download_url': '',
 'files': {'agent_based': ['${PLUGIN_NAME}.py'],
           'agents': ['windows/plugins/${PLUGIN_NAME}.ps1', 'windows/plugins/${PLUGIN_NAME}.cfg.ps1'],
           'graphing': ['${PLUGIN_NAME}.py'],
           'rulesets': ['${PLUGIN_NAME}.py']},
 'name': '${PLUGIN_NAME}',
 'title': 'PKI Certificate Monitor',
 'version': '${VERSION}',
 'version.min_required': '2.3.0',
 'version.packaged': '2.3.0',
 'version.usable_until': None}
EOF

# Create the MKP file (tar.gz format)
echo "Creating MKP package..."
cd "${BUILD_DIR}"
tar -czf "../${OUTPUT_FILE}" *
cd ..

echo ""
echo "=========================================="
echo "Package created: ${OUTPUT_FILE}"
echo "=========================================="
echo ""
echo "Installation instructions:"
echo "1. Upload via Checkmk GUI: Setup → Extension Packages → Upload package"
echo "2. Or use CLI: mkp install ${OUTPUT_FILE}"
echo ""
echo "After installation, deploy the Windows agent plugin to monitored hosts."

# Show package contents
echo ""
echo "Package contents:"
tar -tzf "${OUTPUT_FILE}" | head -20
