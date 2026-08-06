#!/usr/bin/env bash
set -euo pipefail

deployment_host="${FIRMATLAS_DEPLOY_HOST:-satc_cloud}"
remote_root="${FIRMATLAS_REMOTE_ROOT:-/home/fitz/apps/firmatlas}"
with_database=false

usage() {
  echo "Usage: $0 [--with-database]"
}

while (($#)); do
  case "$1" in
    --with-database) with_database=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

if ! command -v node >/dev/null 2>&1; then
  bundled_node_dir="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin"
  if [[ -x "$bundled_node_dir/node" ]]; then
    export PATH="$bundled_node_dir:$PATH"
  else
    echo "Deployment refused: Node.js is not available." >&2
    exit 1
  fi
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Deployment refused: the local worktree is not clean." >&2
  exit 1
fi

revision="$(git rev-parse HEAD)"
release_dir="$remote_root/releases/$revision"

echo "Verifying revision $revision before deployment..."
make test
pnpm --dir apps/console test
pnpm --dir apps/console build

ssh -o BatchMode=yes "$deployment_host" \
  "test \"\$(loginctl show-user \"\$(id -un)\" -p Linger --value)\" = yes" || {
  echo "Deployment refused: persistent user services (linger) are not enabled remotely." >&2
  exit 1
}

ssh -o BatchMode=yes "$deployment_host" \
  "mkdir -p '$release_dir' '$remote_root/shared/var' \"\$HOME/.config/systemd/user\""

rsync -az --delete \
  --exclude='.git/' \
  --exclude='apps/console/node_modules/' \
  --exclude='var/' \
  "$repository_root/" "$deployment_host:$release_dir/"

if $with_database; then
  snapshot_dir="$(mktemp -d)"
  trap 'rm -rf "$snapshot_dir"' EXIT
  echo "Creating a consistent SQLite snapshot..."
  sqlite3 "$repository_root/var/firmatlas.db" ".backup '$snapshot_dir/firmatlas.db'"
  rsync -azh --partial --progress \
    "$snapshot_dir/firmatlas.db" \
    "$deployment_host:$remote_root/shared/var/firmatlas.db.incoming"
  ssh -o BatchMode=yes "$deployment_host" \
    "systemctl --user stop firmatlas.service 2>/dev/null || true; \
     if test -f '$remote_root/shared/var/firmatlas.db'; then \
       mv '$remote_root/shared/var/firmatlas.db' '$remote_root/shared/var/firmatlas.db.previous'; \
     fi; \
     mv '$remote_root/shared/var/firmatlas.db.incoming' '$remote_root/shared/var/firmatlas.db'"
fi

ssh -o BatchMode=yes "$deployment_host" \
  "install -m 0644 '$release_dir/deploy/firmatlas.service' \"\$HOME/.config/systemd/user/firmatlas.service\"; \
   ln -sfn '$release_dir' '$remote_root/current'; \
   systemctl --user daemon-reload; \
   systemctl --user enable firmatlas.service >/dev/null; \
   systemctl --user restart firmatlas.service"

echo "Waiting for the remote health check..."
for attempt in {1..90}; do
  if ssh -o BatchMode=yes "$deployment_host" \
    "curl --fail --silent --max-time 5 http://127.0.0.1:18080/api/health >/dev/null"; then
    break
  fi
  if [[ "$attempt" == 90 ]]; then
    echo "Deployment failed: remote health check did not become ready." >&2
    ssh -o BatchMode=yes "$deployment_host" \
      "systemctl --user --no-pager status firmatlas.service" || true
    exit 1
  fi
  sleep 2
done

remote_revision="$(ssh -o BatchMode=yes "$deployment_host" \
  "basename \"\$(readlink '$remote_root/current')\"")"
if [[ "$remote_revision" != "$revision" ]]; then
  echo "Deployment failed: remote revision is $remote_revision, expected $revision." >&2
  exit 1
fi

ssh -o BatchMode=yes "$deployment_host" \
  "curl --fail --silent --max-time 10 http://127.0.0.1:18080/ | grep -q '<title>FirmAtlas'"

echo "FirmAtlas $revision is running on $deployment_host:18080."
