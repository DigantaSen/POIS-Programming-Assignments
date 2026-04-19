#!/usr/bin/env bash
set -euo pipefail

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

# Ensure required file exists
if [[ ! -f "$project_root/workflow/state.json" ]]; then
  echo "Missing workflow/state.json"
  exit 1
fi

cd "$parent_dir"

temp_dir="temp_${project_name}_$$"
cp -r "$project_name" "$temp_dir"

# Cleanup unwanted files
rm -rf "$temp_dir/.venv"
find "$temp_dir" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$temp_dir" -name "*.pyc" -delete 2>/dev/null || true
rm -rf "$temp_dir/webapp/node_modules"
rm -rf "$temp_dir/webapp/dist"
find "$temp_dir" -name ".DS_Store" -delete 2>/dev/null || true
find "$temp_dir" -name "*.egg-info" -type d -exec rm -rf {} + 2>/dev/null || true

# 🔥 Let PowerShell handle paths correctly
powershell.exe -Command "
\$src = Resolve-Path '$temp_dir';
\$dest = Join-Path (Resolve-Path .) '$zip_name';
Compress-Archive -Path \$src -DestinationPath \$dest -Force
"

# Cleanup
rm -rf "$temp_dir"

echo "Created: $parent_dir/$zip_name"
echo "Send this zip file in WhatsApp group."