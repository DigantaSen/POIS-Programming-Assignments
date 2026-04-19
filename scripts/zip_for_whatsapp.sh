#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/zip_for_whatsapp.sh <MemberName>
# Example:
#   ./scripts/zip_for_whatsapp.sh Kushal

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <MemberName>"
  exit 1
fi

member="$1"
project_root="$(cd "$(dirname "$0")/.." && pwd)"
project_name="$(basename "$project_root")"
parent_dir="$(dirname "$project_root")"
timestamp="$(date +%Y%m%d_%H%M%S)"
zip_name="${project_name}_${member}_${timestamp}.zip"
zip_path="${parent_dir}/${zip_name}"

# Ensure clean state file exists. We do not overwrite user progress automatically.
if [[ ! -f "$project_root/workflow/state.json" ]]; then
  echo "Missing workflow/state.json"
  exit 1
fi

cd "$parent_dir"

# Build zip while excluding environment/build/cache artifacts.
zip -r "$zip_path" "$project_name" \
  -x "${project_name}/.venv/*" \
  -x "${project_name}/**/__pycache__/*" \
  -x "${project_name}/**/*.pyc" \
  -x "${project_name}/webapp/node_modules/*" \
  -x "${project_name}/webapp/dist/*" \
  -x "${project_name}/.DS_Store" \
  -x "${project_name}/src/*.egg-info/*"

echo "Created: $zip_path"
echo "Send this zip file in WhatsApp group."
