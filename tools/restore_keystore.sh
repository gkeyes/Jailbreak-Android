#!/usr/bin/env bash
# Restore only the current fixed release key from Actions Secrets.
# Passwords remain in the job environment; no repository files or historical fallbacks are read.
set -euo pipefail
for name in LHASA_KEYSTORE_B64 LHASA_STORE_PASSWORD LHASA_KEY_ALIAS LHASA_KEY_PASSWORD; do
  if [ -z "${!name:-}" ]; then
    echo "::error::Required Actions secret $name is missing"
    exit 1
  fi
done
umask 077
signing_dir="$RUNNER_TEMP/lhasa26-signing"
mkdir -p "$signing_dir"
keystore="$signing_dir/release.jks"
certificate="$signing_dir/certificate.der"
if ! printf '%s' "$LHASA_KEYSTORE_B64" | base64 --decode > "$keystore"; then
  echo "::error::LHASA_KEYSTORE_B64 is not valid base64"
  exit 1
fi
if [ ! -s "$keystore" ]; then
  echo "::error::The configured release keystore is empty"
  exit 1
fi
if ! keytool -exportcert -keystore "$keystore" -alias "$LHASA_KEY_ALIAS" \
  -storepass:env LHASA_STORE_PASSWORD -file "$certificate" > /dev/null 2>&1; then
  echo "::error::The configured keystore, store password or key alias is invalid"
  exit 1
fi
actual=$(sha256sum "$certificate" | awk '{print $1}')
if [ "$actual" != "$LHASA_SIGNING_CERT_SHA256" ]; then
  echo "::error::The signing certificate does not match the fixed release identity"
  exit 1
fi
echo "LHASA_KEYSTORE=$keystore" >> "$GITHUB_ENV"
echo "Release signing certificate verified"

