#!/bin/sh
# cPanel cron'u çalıştırır: depodaki site dosyalarını ~/odyobuk.com'a kopyalar. Yalnız yeni commit gelince iş yapar.
# Önceki sayfa index-onceki.html olarak durur (tek yedek, birikmez).
set -e
cd "$(dirname "$0")"
H=$(git rev-parse HEAD)
[ "$(cat "$HOME/.odyobuk_son" 2>/dev/null)" = "$H" ] && exit 0
HEDEF="$HOME/odyobuk.com"
mkdir -p "$HEDEF/fonts"
[ -f "$HEDEF/index.html" ] && cp "$HEDEF/index.html" "$HEDEF/index-onceki.html"
cp fonts/*.woff2 fonts/OFL.txt "$HEDEF/fonts/"
cp index.html "$HEDEF/index.html"
# ücretsiz deneme (odyobuk.com/dene): yalnız bu beş dosya; ayar web kökü dışında (~/odyobuk-deneme/ayar.php)
if [ -d dene ]; then
  mkdir -p "$HEDEF/dene"
  for f in index.php ortak.php sil.php cloudflare.php .htaccess; do cp "dene/$f" "$HEDEF/dene/$f"; done
fi
[ -f aydinlatma.html ] && cp aydinlatma.html "$HEDEF/aydinlatma.html"
# ana sayfadaki deneme alanının örnekleri (ses + analiz sonucu)
if [ -d ornek ]; then mkdir -p "$HEDEF/ornek"; cp ornek/*.json ornek/*.mp3 "$HEDEF/ornek/"; rm -f "$HEDEF"/ornek/*.m4a; fi
echo "$H" > "$HOME/.odyobuk_son"
