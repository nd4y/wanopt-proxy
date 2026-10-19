#!/usr/bin/env bash
set -euo pipefail
export GOWORK=off GOTOOLCHAIN=go1.27.2 CGO_ENABLED=0
version=${1:?version required}
output=${2:?new output directory required}
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid version' >&2; exit 1; }
[[ ! -e "$output" ]] || { echo 'Output already exists' >&2; exit 1; }
mkdir -p "$output"
output=$(cd "$output" && pwd)
repo=$(git rev-parse --show-toplevel)
work=$(mktemp -d -t wanopt-release.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
for platform in linux windows; do
  mkdir -p "$work/$platform"
  ext=''; [[ "$platform" != windows ]] || ext='.exe'
  for target in client server keygen; do
    GOOS="$platform" GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$work/$platform/wanopt-$target$ext" "./cmd/$target"
  done
  GOOS="$platform" GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$work/$platform/wanbench$ext" ./tools/wanbench
done
# Two independent output builds: the binaries, rather than their timestamps,
# must agree. Existing Go cache is shared, source and build flags are identical.
for target in client server keygen; do
  go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$work/rebuilt" "./cmd/$target"
  cmp "$work/rebuilt" "$work/linux/wanopt-$target"
done
CGO_ENABLED=1 bash experiments/bbr/build.sh "$work/bbr"
python3 tools/validation/check.py --bin "$work/linux" --report "$output/reno-release-check.json"
python3 tools/validation/check.py --bin "$work/bbr" --cc bbr --report "$output/bbr-release-check.json"
python3 - "$version" "$output" "$work" "$repo" <<'PY'
import hashlib,json,pathlib,subprocess,sys,tarfile,zipfile
version,out,work,repo=sys.argv[1],pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])
source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
packages=[]
for platform,folder in [('linux-amd64','linux'),('windows-amd64','windows'),('bbr-experimental-linux-amd64','bbr')]:
    files=sorted((work/folder).iterdir())
    if platform.startswith('windows'):
        target=out/f'wanopt-{version}-{platform}.zip'
        with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for path in files: archive.write(path,path.name)
    else:
        target=out/f'wanopt-{version}-{platform}.tar.gz'
        with tarfile.open(target,'w:gz') as archive:
            for path in files: archive.add(path,arcname=path.name)
    packages.append({'asset':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
                     'binaries':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in files}})
manifest={'version':version,'source_commit':source,'protocol':2,'default_controller':'reno',
          'bbr':'experimental, opt-in, separate asset',
          'go':subprocess.check_output(['go','version'],text=True).strip(),
          'patch_sha256':{name:hashlib.sha256((repo/'experiments/bbr'/name).read_bytes()).hexdigest() for name in ['wanopt.patch','quic-go.patch']},
          'normal_binary_rebuild_comparison':'PASS','packages':packages}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
assets=sorted(p for p in out.iterdir() if p.is_file())
(out/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in assets))
PY
