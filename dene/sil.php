<?php
// Yönetici: bir e-posta adresinin bütün deneme kayıtlarını siler (kullanıcı «verilerimi silin» dediğinde).
//   php sil.php kisi@ornek.com
// Yalnız komut satırından çalışır; web'den açılmaz (.htaccess de kapatır).
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require __DIR__ . '/ortak.php';
$e = $argv[1] ?? '';
if (!eposta_gecerli($e)) { fwrite(STDERR, "kullanım: php sil.php <e-posta>\n"); exit(2); }
$n = kisi_sil(ozet(ayar()['ozet_tuzu'], 'e|' . eposta_norm($e)));
echo $n ? "silindi ($n kayıt, oturumları ve kodları dahil)\n" : "bu adresle kayıt yok (kodlar yine silindi)\n";
