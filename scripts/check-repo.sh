#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

failed=0
personal_path_prefix='/Users'
secret_pattern="BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16}|$personal_path_prefix/[^/[:space:]]+/"
while IFS= read -r -d '' path; do
  case "$path" in
    .env.example|config*.example.json|*/config*.example.json) ;;
    .env|.env.*|*/.env|*/.env.*|config*.json|*/config*.json|*.key|*.pem|*.p12|*.pfx|*.log|password|password.txt|.DS_Store|*/.DS_Store|build/*|.cache/*|state/*|reports/*|local-notes/*|secrets/*|credentials/*|node_modules/*|dist/*)
      echo "Publication boundary violation: $path" >&2
      failed=1
      continue
      ;;
  esac
  [[ -f "$path" ]] || continue
  # Print file names only; never print a potentially sensitive match.
  if grep -Eq -- "$secret_pattern" "$path"; then
    echo "Possible secret or personal path: $path" >&2
    failed=1
  fi
  if git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
    if git show ":$path" | grep -E -- "$secret_pattern" >/dev/null; then
      echo "Possible secret or personal path in staged file: $path" >&2
      failed=1
    fi
  fi
done < <(git ls-files --cached --others --exclude-standard -z)

if [[ -f .env.example ]] && grep -Eq '^[A-Z_]+=[[:space:]]*[^[:space:]]' .env.example; then
  echo ".env.example must contain empty credential/proxy values" >&2
  failed=1
fi
if [[ "$failed" != 0 ]]; then exit 1; fi
echo "Repository publication boundary check passed (heuristic; review staged files before publishing)."
