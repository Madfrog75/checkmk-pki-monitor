#!/bin/bash
# Build script for PKI Monitor Checkmk plugin
# Creates an MKP (Checkmk Extension Package) file
# Compatible with Checkmk 2.3.x

set -e

PLUGIN_NAME="pki_monitor"
VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
OUTPUT_FILE="${PLUGIN_NAME}-${VERSION}.mkp"

echo "Building ${PLUGIN_NAME} version ${VERSION} (Checkmk 2.3 format)..."

# Clean previous build
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Create staging directory that matches the final Checkmk structure
STAGING_DIR="${BUILD_DIR}/staging"
mkdir -p "${STAGING_DIR}"

# Create the 2.3 directory structure
# Agent-based plugins go to lib/python3/cmk/base/plugins/agent_based/
mkdir -p "${STAGING_DIR}/lib/python3/cmk/base/plugins/agent_based"
cp "${SCRIPT_DIR}/local/lib/python3/cmk/base/plugins/agent_based/"*.py \
   "${STAGING_DIR}/lib/python3/cmk/base/plugins/agent_based/"

# WATO rulesets go to lib/python3/cmk/gui/plugins/wato/
mkdir -p "${STAGING_DIR}/lib/python3/cmk/gui/plugins/wato"
cp "${SCRIPT_DIR}/local/lib/python3/cmk/gui/plugins/wato/"*.py \
   "${STAGING_DIR}/lib/python3/cmk/gui/plugins/wato/"

# Metrics/graphing go to lib/python3/cmk/gui/plugins/metrics/
mkdir -p "${STAGING_DIR}/lib/python3/cmk/gui/plugins/metrics"
cp "${SCRIPT_DIR}/local/lib/python3/cmk/gui/plugins/metrics/"*.py \
   "${STAGING_DIR}/lib/python3/cmk/gui/plugins/metrics/"

# Bakery plugin (Enterprise Edition - agent deployment)
mkdir -p "${STAGING_DIR}/lib/python3/cmk/base/cee/plugins/bakery"
cp "${SCRIPT_DIR}/local/lib/python3/cmk/base/cee/plugins/bakery/"*.py \
   "${STAGING_DIR}/lib/python3/cmk/base/cee/plugins/bakery/"

# Windows agent plugins go to agents/windows/plugins/
mkdir -p "${STAGING_DIR}/agents/windows/plugins"
cp "${SCRIPT_DIR}/local/share/check_mk/agents/windows/plugins/"*.ps1 \
   "${STAGING_DIR}/agents/windows/plugins/"

# Create package info (Python dict format for 2.3)
cat > "${BUILD_DIR}/info" << EOF
{'author': 'PKI Monitor Plugin',
 'description': 'Monitor Microsoft Active Directory Certificate Services (ADCS) and track certificate expiration across your PKI infrastructure.',
 'download_url': '',
 'files': {'lib': ['python3/cmk/base/plugins/agent_based/${PLUGIN_NAME}.py',
                   'python3/cmk/gui/plugins/wato/${PLUGIN_NAME}.py',
                   'python3/cmk/gui/plugins/metrics/${PLUGIN_NAME}.py',
                   'python3/cmk/base/cee/plugins/bakery/${PLUGIN_NAME}.py'],
           'agents': ['windows/plugins/${PLUGIN_NAME}.ps1',
                      'windows/plugins/${PLUGIN_NAME}.cfg.ps1']},
 'name': '${PLUGIN_NAME}',
 'title': 'PKI Certificate Monitor',
 'version': '${VERSION}',
 'version.min_required': '2.3.0',
 'version.packaged': '2.3.0',
 'version.usable_until': '2.4.0'}
EOF

# Create individual tar archives for each file category
# IMPORTANT: Paths inside tar must match the info file paths (no category prefix)
echo "Creating tar archives..."

# Create lib tar archive - cd into lib dir so paths start with python3/
cd "${STAGING_DIR}/lib"
tar -cf "${BUILD_DIR}/lib.tar" python3

# Create agents tar archive - cd into agents dir so paths start with windows/
cd "${STAGING_DIR}/agents"
tar -cf "${BUILD_DIR}/agents.tar" windows

cd "${BUILD_DIR}"

# Clean up staging directory
rm -rf "${STAGING_DIR}"

# Create the MKP file (tar.gz containing tar archives and info file)
echo "Creating MKP package..."
tar -czf "${SCRIPT_DIR}/${OUTPUT_FILE}" info lib.tar agents.tar

echo ""
echo "=========================================="
echo "Package created: ${SCRIPT_DIR}/${OUTPUT_FILE}"
echo "=========================================="
echo ""
echo "Installation instructions for Checkmk 2.3:"
echo "1. Copy to container: docker cp ${OUTPUT_FILE} <container>:/tmp/"
echo "2. Add package: docker exec <container> su - cmk -c 'mkp add /tmp/${OUTPUT_FILE}'"
echo "3. Enable: docker exec <container> su - cmk -c 'mkp enable ${PLUGIN_NAME} ${VERSION}'"
echo "4. Restart: docker exec <container> su - cmk -c 'cmk -R'"
echo ""
echo "After installation, deploy the Windows agent plugin to monitored hosts."

# Show package contents
echo ""
echo "Package contents:"
tar -tzf "${SCRIPT_DIR}/${OUTPUT_FILE}"
