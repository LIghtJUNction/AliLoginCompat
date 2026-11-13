#!/usr/bin/env python3
"""Build and sign locally; signing material remains in ignored .signing/."""
import hashlib,json,os,pathlib,secrets,subprocess
root=pathlib.Path(__file__).resolve().parent.parent
os.umask(0o077)
subprocess.run([str(root/'gradlew'),':app:assembleRelease','--console=plain'],cwd=root,check=True)
sdk=os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
if not sdk:
    for line in (root/'local.properties').read_text().splitlines():
        if line.startswith('sdk.dir='):sdk=line.split('=',1)[1]
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
output=root/'artifacts';output.mkdir(exist_ok=True)
apk=output/f'AliLoginCompat-{metadata["versionName"]}-arm64.apk'
subprocess.run([str(signer),'sign','--ks',str(key),'--ks-key-alias','release','--ks-pass','file:'+str(password),'--out',str(apk),str(directory/metadata['outputFile'])],check=True)
subprocess.run([str(signer),'verify','--verbose',str(apk)],check=True)
digest=hashlib.sha256(apk.read_bytes()).hexdigest()
(output/(apk.name+'.sha256')).write_text(digest+'  '+apk.name+'\n')
print('Signed APK:',apk)
print('SHA256:',digest)
