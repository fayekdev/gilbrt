"""Vendor the Three.js release recorded in version.json, or current npm release on first run."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

output = Path(__file__).resolve().parents[1] / 'public' / 'vendor' / 'three'
record = output / 'version.json'
locked = json.loads(record.read_text()) if record.exists() else None
version = locked['version'] if locked else 'latest'
with urllib.request.urlopen(f'https://registry.npmjs.org/three/{version}', timeout=30) as response:
    metadata = json.load(response)
with urllib.request.urlopen(metadata['dist']['tarball'], timeout=60) as response:
    package = response.read()
expected = locked['integrity'] if locked else metadata['dist']['integrity']
actual = 'sha512-' + base64.b64encode(hashlib.sha512(package).digest()).decode()
if actual != expected:
    raise RuntimeError('Three.js package integrity check failed')
output.mkdir(parents=True, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(package), mode='r:gz') as archive:
    for source, target in [('package/build/three.module.js', 'three.module.js'),
                           ('package/build/three.core.js', 'three.core.js'),
                           ('package/LICENSE', 'LICENSE')]:
        (output / target).write_bytes(archive.extractfile(source).read())
record.write_text(json.dumps({'version': metadata['version'], 'source': 'https://github.com/mrdoob/three.js',
                             'integrity': actual}, indent=2) + '\n')
print(f"Vendored Three.js {metadata['version']}; npm SHA-512 verified")
