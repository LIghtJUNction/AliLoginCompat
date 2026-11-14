#!/usr/bin/env python3
"""Build and sign locally; signing material remains in ignored .signing/."""
import hashlib,json,os,pathlib,platform,re,secrets,subprocess,tempfile,zipfile
root=pathlib.Path(__file__).resolve().parent.parent
os.umask(0o077)
subprocess.run([str(root/'gradlew'),':app:assembleRelease','--console=plain'],cwd=root,check=True)
sdk=None
if (root/'local.properties').exists():
    for line in (root/'local.properties').read_text().splitlines():
        if line.startswith('sdk.dir='):sdk=line.split('=',1)[1]
if not sdk:sdk=os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
if not sdk:raise SystemExit('Android SDK path missing')
signer=pathlib.Path(sdk)/'build-tools/36.0.0/apksigner'
signing=root/'.signing';signing.mkdir(mode=0o700,exist_ok=True)
password=signing/'password';key=signing/'release.jks'
if not password.exists():password.write_text(secrets.token_urlsafe(32));password.chmod(0o600)
env=dict(os.environ);env['ALI_KEYSTORE_PASSWORD']=password.read_text()
if not key.exists():
    subprocess.run(['keytool','-genkeypair','-keystore',str(key),'-storepass:env','ALI_KEYSTORE_PASSWORD','-keypass:env','ALI_KEYSTORE_PASSWORD','-alias','release','-keyalg','RSA','-keysize','3072','-validity','10000','-dname','CN=AliLoginCompat Development'],env=env,check=True,capture_output=True)
    key.chmod(0o600)
directory=root/'app/build/outputs/apk/release'
metadata=json.loads((directory/'output-metadata.json').read_text())['elements'][0]
# Verify the packaged ABI, not just the source export list. A stale link can build
# successfully while Java fails with UnsatisfiedLinkError on the device.
ndk_version=re.search(r'ndkVersion\s*=\s*"([^"]+)"',(root/'app/build.gradle.kts').read_text()).group(1)
nm_candidates=list((pathlib.Path(sdk)/'ndk'/ndk_version/'toolchains/llvm/prebuilt').glob(platform.system().lower()+'-*/bin/llvm-nm'))
if len(nm_candidates)!=1:raise SystemExit('Cannot locate the build NDK llvm-nm')
required={'native_init'}
for source in (root/'app/src/main/java').rglob('*.java'):
    text=source.read_text()
    methods=re.findall(r'\bnative\s+[\w.\[\]]+\s+(\w+)\s*\(',text)
    if not methods:continue
    package=re.search(r'\bpackage\s+([\w.]+)\s*;',text).group(1)
    owner=(package+'.'+source.stem).replace('_','_1').replace('.','_')
    required.update('Java_'+owner+'_'+method.replace('_','_1') for method in methods)
with tempfile.TemporaryDirectory(prefix='ali-jni-check-') as temporary:
    library=pathlib.Path(temporary)/'libalilogincompat.so'
    with zipfile.ZipFile(directory/metadata['outputFile']) as archive:
        library.write_bytes(archive.read('lib/arm64-v8a/libalilogincompat.so'))
    result=subprocess.run([str(nm_candidates[0]),'-D','--defined-only',str(library)],check=True,capture_output=True,text=True)
    exported={line.split()[-1].split('@')[0] for line in result.stdout.splitlines() if line.split()}
    missing=required-exported
    if missing:raise SystemExit('Missing packaged native exports: '+', '.join(sorted(missing)))
print('Packaged JNI exports verified:',len(required))
output=root/'artifacts';output.mkdir(exist_ok=True)
apk=output/f'AliLoginCompat-{metadata["versionName"]}-arm64.apk'
subprocess.run([str(signer),'sign','--ks',str(key),'--ks-key-alias','release','--ks-pass','file:'+str(password),'--out',str(apk),str(directory/metadata['outputFile'])],check=True)
subprocess.run([str(signer),'verify','--verbose',str(apk)],check=True)
digest=hashlib.sha256(apk.read_bytes()).hexdigest()
(output/(apk.name+'.sha256')).write_text(digest+'  '+apk.name+'\n')
print('Signed APK:',apk)
print('SHA256:',digest)
