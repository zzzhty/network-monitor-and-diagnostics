#!/usr/bin/env bash
# Bootstrap only. All installed lifecycle operations belong to nmd.
set -euo pipefail
repository=${NMD_REPOSITORY:-https://github.com/zzzhty/network-monitor-and-diagnostics.git}
script_dir=
if [[ -f ${BASH_SOURCE[0]:-} ]]; then
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi
if [[ -n $script_dir && -f $script_dir/scripts/manager.py ]]; then
  exec python3 "$script_dir/scripts/manager.py" bootstrap "$@"
fi
# Streamed private-repository installs use existing Git credentials, never tokens
# in URLs. NMD_REPOSITORY may select an authenticated SSH remote instead.
bootstrap_dir=$(mktemp -d)
trap 'rm -rf -- "$bootstrap_dir"' EXIT
git clone --depth 1 --branch main -- "$repository" "$bootstrap_dir/repo"
if [[ -t 1 && -r /dev/tty ]]; then
  python3 "$bootstrap_dir/repo/scripts/manager.py" bootstrap "$@" </dev/tty
else
  python3 "$bootstrap_dir/repo/scripts/manager.py" bootstrap "$@" </dev/null
fi
