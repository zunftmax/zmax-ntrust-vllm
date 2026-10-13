#!/usr/bin/env bash
# Run only on the configured Linux image build host, after hardware acceptance.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${NTRUST_UQ_RELEASE_CONFIG:?Supply an independently approved uq release JSON; no release is selected automatically}"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo 'uq image acquisition must run on the configured x86-64 Linux build host' >&2
  exit 1
}
uq_record=$(python3 image/uq-release.py "$NTRUST_UQ_RELEASE_CONFIG")
mkdir -p build
uq_stage=$(mktemp -d "$PWD/build/uq-stage.XXXXXX")
trap 'rm -rf -- "$uq_stage"' EXIT
printf '%s\n' "$uq_record" > "$uq_stage/release.json"
mapfile -t uq_pins < <(python3 - "$uq_stage/release.json" <<'PINS'
import json, sys
record = json.load(open(sys.argv[1]))
for key in ('release_tag', 'source_sha', 'binary_sha256', 'target'):
    print(record[key])
PINS
)
[[ ${#uq_pins[@]} == 4 ]]
if [[ -e build/uq || -L build/uq ]]; then
  [[ -d build/uq && ! -L build/uq ]] || { echo 'Invalid uq staging directory' >&2; exit 1; }
  python3 image/uq-release.py build/uq/release.json build/uq/uq > "$uq_stage/existing.json"
  cmp "$uq_stage/release.json" "$uq_stage/existing.json" || {
    echo 'Staged uq uses different approval pins; remove build/uq explicitly before replacing it' >&2
    exit 1
  }
  # Recheck release provenance for an existing dependency, too.
  gh attestation verify build/uq/uq \
    --repo ZUNFTMAX/zmax-universal-attestations \
    --signer-workflow ZUNFTMAX/zmax-universal-attestations/.github/workflows/release.yml \
    --source-digest "${uq_pins[1]}" \
    --predicate-type https://slsa.dev/provenance/v1 --deny-self-hosted-runners
  exit 0
fi
bash image/fetch-verified-uq.sh "${uq_pins[@]}" "$uq_stage/uq"
python3 image/uq-release.py "$uq_stage/release.json" "$uq_stage/uq" >/dev/null
mv "$uq_stage" build/uq
