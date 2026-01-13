#!/bin/bash
# Build script for PKI Monitor Checkmk plugin
# Creates an MKP (Checkmk Extension Package) file
# Compatible with Checkmk 2.4+

set -e

PLUGIN_NAME="pki_monitor"
VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
OUTPUT_FILE="${PLUGIN_NAME}-${VERSION}.mkp"

echo "Building ${PLUGIN_NAME} version ${VERSION} (Checkmk 2.4 format)..."

# Clean previous build
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Create staging directories for tar archives
STAGING_DIR="${BUILD_DIR}/staging"
mkdir -p "${STAGING_DIR}/cmk_addons_plugins"
mkdir -p "${STAGING_DIR}/agents"

# Create the cmk_addons_plugins structure (new 2.4 format)
echo "Creating package structure..."

# Copy agent_based plugins
mkdir -p "${STAGING_DIR}/cmk_addons_plugins/${PLUGIN_NAME}/agent_based"
cp "${SCRIPT_DIR}/local/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/agent_based/"*.py \
   "${STAGING_DIR}/cmk_addons_plugins/${PLUGIN_NAME}/agent_based/"

# Copy rulesets
mkdir -p "${STAGING_DIR}/cmk_addons_plugins/${PLUGIN_NAME}/rulesets"
cp "${SCRIPT_DIR}/local/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/rulesets/"*.py \
   "${STAGING_DIR}/cmk_addons_plugins/${PLUGIN_NAME}/rulesets/"

# Copy graphing
mkdir -p "${STAGING_DIR}/cmk_addons_plugins/${PLUGIN_NAME}/graphing"
cp "${SCRIPT_DIR}/local/lib/python3/cmk_addons/plugins/${PLUGIN_NAME}/graphing/"*.py \
   "${STAGING_DIR}/cmk_addons_plugins/${PLUGIN_NAME}/graphing/"

# Copy Windows agent plugins
mkdir -p "${STAGING_DIR}/agents/windows/plugins"
cp "${SCRIPT_DIR}/local/share/check_mk/agents/windows/plugins/"*.ps1 \
   "${STAGING_DIR}/agents/windows/plugins/"

# Create individual tar archives for each category
echo "Creating tar archives..."
cd "${STAGING_DIR}/cmk_addons_plugins"
tar -cf "${BUILD_DIR}/cmk_addons_plugins.tar" ${PLUGIN_NAME}
cd "${STAGING_DIR}/agents"
tar -cf "${BUILD_DIR}/agents.tar" windows
cd "${BUILD_DIR}"

# Create package info (Python dict format for 2.4)
cat > "${BUILD_DIR}/info" << EOF
{'author': 'PKI Monitor Plugin',
 'description': 'Monitor Microsoft Active Directory Certificate Services (ADCS) and track certificate expiration across your PKI infrastructure.',
 'download_url': '',
 'files': {'cmk_addons_plugins': ['${PLUGIN_NAME}/agent_based/${PLUGIN_NAME}.py',
                                   '${PLUGIN_NAME}/graphing/${PLUGIN_NAME}.py',
                                   '${PLUGIN_NAME}/rulesets/${PLUGIN_NAME}.py'],
           'agents': ['windows/plugins/${PLUGIN_NAME}.ps1',
                      'windows/plugins/${PLUGIN_NAME}.cfg.ps1']},
 'name': '${PLUGIN_NAME}',
 'title': 'PKI Certificate Monitor',
 'version': '${VERSION}',
 'version.min_required': '2.4.0',
 'version.packaged': '2.4.0',
 'version.usable_until': None}
EOF

# Create JSON version of info
cat > "${BUILD_DIR}/info.json" << EOF
{
  "author": "PKI Monitor Plugin",
  "description": "Monitor Microsoft Active Directory Certificate Services (ADCS) and track certificate expiration across your PKI infrastructure.",
  "download_url": "",
  "files": {
    "cmk_addons_plugins": [
      "${PLUGIN_NAME}/agent_based/${PLUGIN_NAME}.py",
      "${PLUGIN_NAME}/graphing/${PLUGIN_NAME}.py",
      "${PLUGIN_NAME}/rulesets/${PLUGIN_NAME}.py"
    ],
    "agents": [
      "windows/plugins/${PLUGIN_NAME}.ps1",
      "windows/plugins/${PLUGIN_NAME}.cfg.ps1"
    ]
  },
  "name": "${PLUGIN_NAME}",
  "title": "PKI Certificate Monitor",
  "version": "${VERSION}",
  "version.min_required": "2.4.0",
  "version.packaged": "2.4.0",
  "version.usable_until": null
}
EOF

# Clean up staging directory
rm -rf "${STAGING_DIR}"

# Create the MKP file (tar.gz containing tar archives and info files)
echo "Creating MKP package..."
tar -czf "${SCRIPT_DIR}/${OUTPUT_FILE}" info info.json cmk_addons_plugins.tar agents.tar

echo ""
echo "=========================================="
echo "Package created: ${SCRIPT_DIR}/${OUTPUT_FILE}"
echo "=========================================="
echo ""
echo "Installation instructions:"
echo "1. Copy to container: docker cp ${OUTPUT_FILE} <container>:/tmp/"
echo "2. Add package: docker exec <container> su - cmk -c 'mkp add /tmp/${OUTPUT_FILE}'"
echo "3. Enable: docker exec <container> su - cmk -c 'mkp enable ${PLUGIN_NAME} ${VERSION}'"
echo ""
echo "After installation, deploy the Windows agent plugin to monitored hosts."

# Show package contents
echo ""
echo "Package contents:"
tar -tzf "${SCRIPT_DIR}/${OUTPUT_FILE}" | head -20
