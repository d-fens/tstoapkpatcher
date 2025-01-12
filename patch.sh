#!/bin/bash

# TODO: fix this
#echo "$APK_SHA256SUM $APK_FILE" | sha256sum --check --status

echo "Decompiling APK"
java -jar /app/apktool.jar d "$APK_FILE" -o "$SOURCE_OUTPUT" -f

echo "Patching SO files (DLC URL)"
python3 patch_native.py

echo "Patching Gameserver API URL"
grep -rl "https://prod.simpsons-ea.com" "$SOURCE_OUTPUT" | xargs -r sed -i "s|https://prod.simpsons-ea.com|${GAMESERVER_URL}|g"
echo "Patching Director URL"
grep -rl "https://syn-dir.sn.eamobile.com" "$SOURCE_OUTPUT" | xargs -r sed -i "s|https://syn-dir.sn.eamobile.com|${DIRECTOR_URL}|g"

echo "Recompiling APK"
java -jar /app/apktool.jar b /apk/decompiled/ -o /apk/patched.apk
echo "Zipalign APK" # force the generation if file exists
/app/android-14/zipalign -v 4 /apk/patched.apk /apk/patched_zipalign.apk -f
# remove apk to avoid confusion
rm -rf /apk/patched.apk

echo "Signing APK"
{ echo "keystorepassword"; echo "keystorepassword"; echo ''; echo ''; echo ''; echo ''; echo ''; echo ''; echo 'yes'; } | keytool -genkeypair -alias key0 -keyalg RSA -keysize 2048 -validity 10000 -keystore /apk/mykeystore.jks
{ echo "keystorepassword"; } | /app/android-14/apksigner sign --ks-key-alias key0 --ks /apk/mykeystore.jks /apk/patched_zipalign.apk

echo "Generating proto files (development)"
mkdir -p /apk/proto
/app/protodec/protodec --grab /apk/decompiled/lib/arm64-v8a/libscorpio.so
mv *.proto /apk/proto
