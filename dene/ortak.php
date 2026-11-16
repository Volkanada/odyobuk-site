<?php
// Ücretsiz deneme, odyobuk.com tarafı: ortak yardımcılar. Tasarım: tasarim/DENEME_EPOSTA.md.
// Bu dosya doğrudan açılmaz (.htaccess); index.php ve sil.php içerir.
declare(strict_types=1);
ini_set('display_errors', '0');                  // hata ayrıntısı ziyaretçiye hiçbir zaman gösterilmez
set_exception_handler(function (Throwable $e): void { genel_hata(get_class($e) . ': ' . $e->getMessage()); });

if (basename($_SERVER['SCRIPT_FILENAME'] ?? '') === 'ortak.php') { http_response_code(404); exit; }

const KOD_OMUR = 600;            // doğrulama kodu 10 dk
const KOD_YANLIS = 5;            // 5 yanlışta kod iptal
const OTURUM_OMUR = 30 * 86400;  // «bu tarayıcı» oturumu 30 gün
const BILET_OMUR = 900;          // deneme bileti 15 dk (stüdyo bundan uzununu reddeder)

// ---------- ayar (web kökü DIŞINDA; depoda yalnız ayar.ornek.php) ----------
function ayar(): array {
    static $a = null;
    if ($a === null) {
        $yol = getenv('ODYOBUK_DENEME_AYAR') ?: dirname(__DIR__, 2) . '/odyobuk-deneme/ayar.php';
        if (!is_file($yol)) { genel_hata('ayar dosyası yok: ' . $yol); }
        $a = require $yol;
        foreach (['db_dsn', 'bilet_sir', 'kimlik_tuzu', 'kod_biberi', 'ozet_tuzu', 'studio_url'] as $k) {
            if (empty($a[$k])) { genel_hata("ayar eksik: $k"); }
        }
    }
    return $a;
}

function genel_hata(string $gunluk): never {
    error_log('odyobuk-deneme: ' . $gunluk);              // ayrıntı yalnız sunucu günlüğüne
    http_response_code(500);
    echo 'Şu an bir sorun var; birkaç dakika sonra yeniden deneyin.';
    exit;
}

// ---------- veritabanı ----------
function db(): PDO {
    static $p = null;
    if ($p === null) {
        $a = ayar();
        try {
            $p = new PDO($a['db_dsn'], $a['db_kullanici'] ?? null, $a['db_sifre'] ?? null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
        } catch (Throwable $e) { genel_hata('veritabanı: ' . $e->getMessage()); }
        if ($p->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') { sqlite_sema($p); }   // yalnız yerel deneme
    }
    return $p;
}

function sqlite_sema(PDO $p): void {
    $p->exec('PRAGMA busy_timeout = 5000');          // eş zamanlı istekler (yerel deneme / test) kilitle beklesin
    $p->exec('CREATE TABLE IF NOT EXISTS deneme_kisi (id INTEGER PRIMARY KEY AUTOINCREMENT, eposta TEXT NOT NULL,
        eposta_ozet TEXT NOT NULL UNIQUE, kimlik TEXT NOT NULL, dogrulama INTEGER, kvkk_onay INTEGER, duyuru_onay INTEGER NOT NULL DEFAULT 0,
        son_deneme INTEGER, deneme_sayisi INTEGER NOT NULL DEFAULT 0, olusturma INTEGER NOT NULL)');
    $p->exec('CREATE TABLE IF NOT EXISTS deneme_kod (id INTEGER PRIMARY KEY AUTOINCREMENT, eposta_ozet TEXT NOT NULL,
        kod_ozet TEXT NOT NULL, tarayici_ozet TEXT NOT NULL, bitis INTEGER NOT NULL, yanlis INTEGER NOT NULL DEFAULT 0, olusturma INTEGER NOT NULL)');
    $p->exec('CREATE TABLE IF NOT EXISTS deneme_oturum (ozet TEXT PRIMARY KEY, kisi_id INTEGER NOT NULL, bitis INTEGER NOT NULL)');
    $p->exec('CREATE TABLE IF NOT EXISTS deneme_sayac (anahtar TEXT PRIMARY KEY, sayi INTEGER NOT NULL, bitis INTEGER NOT NULL)');
}

/** Kısa ömürlü kayıtlar her istekte temizlenir: süresi geçen kodlar ve oturumlar, 24 saatten eski hız kayıtları (IP özetleri dahil). */
function temizle(): void {
    $t = time();
    db()->prepare('DELETE FROM deneme_kod WHERE bitis < ?')->execute([$t]);
    db()->prepare('DELETE FROM deneme_oturum WHERE bitis < ?')->execute([$t]);
    db()->prepare('DELETE FROM deneme_sayac WHERE bitis < ?')->execute([$t]);
}

// ---------- özetler ----------
function ozet(string $tuz, string $deger): string { return hash_hmac('sha256', $deger, $tuz); }

/** E-posta: küçük harf, boşluk kırpılır, yerel kısımdaki «+etiket» atılır (ad+1@ ile sınırsız kimlik olmasın). */
function eposta_norm(string $e): string {
    $e = strtolower(trim($e));
    $at = strrpos($e, '@');
    if ($at === false) { return $e; }
    $yerel = substr($e, 0, $at); $alan = substr($e, $at + 1);
    $arti = strpos($yerel, '+');
    if ($arti !== false && $arti > 0) { $yerel = substr($yerel, 0, $arti); }
    return $yerel . '@' . $alan;
}

function eposta_gecerli(string $e): bool {
    return strlen($e) <= 254 && !preg_match('/[\r\n\0,;<>]/', $e) && filter_var($e, FILTER_VALIDATE_EMAIL) !== false;
}

/** Opak kimlik: stüdyonun gördüğü tek şey (e-posta geri çıkarılamaz). */
function kimlik(string $eposta_norm): string { return substr(ozet(ayar()['kimlik_tuzu'], $eposta_norm), 0, 32); }

// ---------- ziyaretçi adresi (yalnız hız sınırı için, özetlenmiş, en çok 24 saat) ----------
function ip_aralikta(string $ip, string $cidr): bool {
    [$ag, $bit] = array_pad(explode('/', $cidr, 2), 2, null);
    $a = @inet_pton($ip); $b = @inet_pton($ag);
    if ($a === false || $b === false || strlen($a) !== strlen($b)) { return false; }
    $bit = $bit === null ? strlen($a) * 8 : (int)$bit;
    $tam = intdiv($bit, 8); $kalan = $bit % 8;
    if (substr($a, 0, $tam) !== substr($b, 0, $tam)) { return false; }
    if ($kalan === 0) { return true; }
    $m = chr((0xFF << (8 - $kalan)) & 0xFF);
    return (ord($a[$tam]) & ord($m)) === (ord($b[$tam]) & ord($m));
}

function cloudflare_araliklari(): array {
    $a = ayar()['cloudflare_araliklari'] ?? [];
    return $a ?: (require __DIR__ . '/cloudflare.php');
}

/** Hız sınırı anahtarı: CF-Connecting-IP'ye YALNIZ istek gerçekten Cloudflare aralığından geliyorsa güvenilir (uydurma
 *  başlıkla sınır aşılmasın). IPv6 /64'e indirilir (tek kişi bütün /64'ü kullanabilir). */
function istemci_ip(): string {
    $uzak = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $ip = $uzak;
    $cf = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
    if ($cf !== '' && filter_var($cf, FILTER_VALIDATE_IP)) {
        foreach (cloudflare_araliklari() as $c) {
            if (ip_aralikta($uzak, $c)) { $ip = $cf; break; }
        }
    }
    $b = @inet_pton($ip);
    if ($b !== false && strlen($b) === 16) { return bin2hex(substr($b, 0, 8)) . '::/64'; }
    return $ip;
}

// ---------- hız sınırı ----------
/** Sabit pencereli sayaç, ATOMİK: satır yoksa açılır, sonra tek UPDATE ile «sayı < sınır» ise artırılır. Eş zamanlı
 *  istekler sınırı aşamaz (denetle-sonra-yaz yarışı yok). Pencere sınırında en çok iki katına izin verilir (kabul). */
function hiz(string $tur, string $anahtar, int $pencere, int $en_cok): bool {
    $no = intdiv(time(), $pencere);
    $oz = ozet(ayar()['ozet_tuzu'], "$tur|$anahtar|$no");
    $ekle = db()->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite' ? 'INSERT OR IGNORE' : 'INSERT IGNORE';
    db()->prepare("$ekle INTO deneme_sayac (anahtar, sayi, bitis) VALUES (?, 0, ?)")->execute([$oz, ($no + 2) * $pencere]);
    $u = db()->prepare('UPDATE deneme_sayac SET sayi = sayi + 1 WHERE anahtar = ? AND sayi < ?');
    $u->execute([$oz, $en_cok]);
    return $u->rowCount() === 1;
}

/** Bu penceredeki sayaç değeri (artırmadan). */
function sayac_oku(string $tur, string $anahtar, int $pencere): int {
    $oz = ozet(ayar()['ozet_tuzu'], "$tur|$anahtar|" . intdiv(time(), $pencere));
    $s = db()->prepare('SELECT sayi FROM deneme_sayac WHERE anahtar = ? AND bitis > ?'); $s->execute([$oz, time()]);
    return (int)($s->fetch()['sayi'] ?? 0);
}

/** hiz() ile düşülen bir hakkı geri verir (gönderim başarısız / sonraki denetim reddetti). */
function sayac_geri(string $tur, string $anahtar, int $pencere): void {
    $oz = ozet(ayar()['ozet_tuzu'], "$tur|$anahtar|" . intdiv(time(), $pencere));
    db()->prepare('UPDATE deneme_sayac SET sayi = sayi - 1 WHERE anahtar = ? AND sayi > 0')->execute([$oz]);
}

// ---------- kısa ömürlü değerler (deneme_sayac'ın aynı tablosunda; anahtar özet, değer tam sayı, bitişte temizlenir) ----------
function kv_yaz(string $ad, int $deger, int $omur): void {
    $oz = ozet(ayar()['ozet_tuzu'], "kv|$ad");
    db()->prepare('DELETE FROM deneme_sayac WHERE anahtar = ?')->execute([$oz]);
    db()->prepare('INSERT INTO deneme_sayac (anahtar, sayi, bitis) VALUES (?, ?, ?)')->execute([$oz, $deger, time() + $omur]);
}
/** [değer, bitiş] ya da null (yok / süresi geçmiş). */
function kv_oku(string $ad): ?array {
    $s = db()->prepare('SELECT sayi, bitis FROM deneme_sayac WHERE anahtar = ? AND bitis > ?');
    $s->execute([ozet(ayar()['ozet_tuzu'], "kv|$ad"), time()]);
    $r = $s->fetch();
    return $r ? [(int)$r['sayi'], (int)$r['bitis']] : null;
}
/** Atomik «yoksa al»: anahtar boşsa (ya da süresi geçmişse) $omur sn için alınır ve true döner; doluysa false.
 *  Aynı anda gelen iki istekten yalnız biri alır (birincil anahtar). */
function kv_al(string $ad, int $omur): bool {
    $oz = ozet(ayar()['ozet_tuzu'], "kv|$ad");
    db()->prepare('DELETE FROM deneme_sayac WHERE anahtar = ? AND bitis <= ?')->execute([$oz, time()]);
    $ekle = db()->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite' ? 'INSERT OR IGNORE' : 'INSERT IGNORE';
    $s = db()->prepare("$ekle INTO deneme_sayac (anahtar, sayi, bitis) VALUES (?, 1, ?)");
    $s->execute([$oz, time() + $omur]);
    return $s->rowCount() === 1;
}
function kv_sil(string $ad): void { db()->prepare('DELETE FROM deneme_sayac WHERE anahtar = ?')->execute([ozet(ayar()['ozet_tuzu'], "kv|$ad")]); }

// ---------- basit doğrulama sorusu (15 dk'da 3 koddan sonra; kilit yok) ----------
// Yanıt sunucuda (özet anahtarla), tarayıcı çerezine (od_soru) bağlı, tek kullanımlık, 5 dk ömürlü; yanlışta yeni soru.
const SORU_OMUR = 300;
function soru_jetonu(): string {
    $t = (string)($_COOKIE['od_soru'] ?? '');
    if (!preg_match('/^[A-Za-z0-9_-]{32}$/', $t)) {
        $t = b64(random_bytes(24));
        setcookie('od_soru', $t, ['path' => '/dene', 'secure' => guvenli(), 'httponly' => true, 'samesite' => 'Strict']);
        $_COOKIE['od_soru'] = $t;
    }
    return $t;
}
function soru_uret(): string {
    $a = random_int(2, 9); $b = random_int(2, 9);
    kv_yaz('soru|' . soru_jetonu(), $a + $b, SORU_OMUR);
    return "$a + $b";
}
function soru_dogru(string $cevap): bool {
    $ad = 'soru|' . soru_jetonu();
    $v = kv_oku($ad);
    kv_sil($ad);                                     // tek kullanımlık: doğru da yanlış da olsa soru biter
    return $v !== null && preg_match('/^\s*\d{1,3}\s*$/', $cevap) && (int)$cevap === $v[0];
}

// ---------- CSRF (çift gönderim: SameSite=Strict çerez + gizli alan) ----------
function csrf(): string {
    if (empty($_COOKIE['od_csrf']) || !preg_match('/^[a-f0-9]{64}$/', (string)$_COOKIE['od_csrf'])) {
        $t = bin2hex(random_bytes(32));
        setcookie('od_csrf', $t, ['path' => '/dene', 'secure' => guvenli(), 'httponly' => true, 'samesite' => 'Strict']);
        $_COOKIE['od_csrf'] = $t;
    }
    return $_COOKIE['od_csrf'];
}

function csrf_dogru(): bool {
    $c = (string)($_COOKIE['od_csrf'] ?? ''); $f = (string)($_POST['csrf'] ?? '');
    return $c !== '' && hash_equals($c, $f);
}

function guvenli(): bool {
    // istemcinin X-Forwarded-Proto'suna güvenilmez: sunucunun HTTPS değişkeni ya da ayar
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || !empty(ayar()['https']);
}

// ---------- «bu tarayıcı» oturumu (30 gün, iptal edilebilir; veritabanında yalnız özeti) ----------
function oturum_kisi(): ?array {
    $t = (string)($_COOKIE['od_deneme'] ?? '');
    if (!preg_match('/^[A-Za-z0-9_-]{43}$/', $t)) { return null; }
    $s = db()->prepare('SELECT k.* FROM deneme_oturum o JOIN deneme_kisi k ON k.id = o.kisi_id WHERE o.ozet = ? AND o.bitis > ?');
    $s->execute([ozet(ayar()['ozet_tuzu'], $t), time()]);
    return $s->fetch() ?: null;
}

function oturum_ac(int $kisi_id): void {
    $t = b64(random_bytes(32));
    db()->prepare('INSERT INTO deneme_oturum (ozet, kisi_id, bitis) VALUES (?, ?, ?)')
        ->execute([ozet(ayar()['ozet_tuzu'], $t), $kisi_id, time() + OTURUM_OMUR]);
    setcookie('od_deneme', $t, ['expires' => time() + OTURUM_OMUR, 'path' => '/dene', 'secure' => guvenli(),
        'httponly' => true, 'samesite' => 'Lax']);
}

function oturum_kapat(): void {
    $t = (string)($_COOKIE['od_deneme'] ?? '');
    if ($t !== '') { db()->prepare('DELETE FROM deneme_oturum WHERE ozet = ?')->execute([ozet(ayar()['ozet_tuzu'], $t)]); }
    setcookie('od_deneme', '', ['expires' => 1, 'path' => '/dene', 'secure' => guvenli(), 'httponly' => true, 'samesite' => 'Lax']);
}

// ---------- deneme bileti (web/deneme.py bilet_coz ile birebir) ----------
function b64(string $b): string { return rtrim(strtr(base64_encode($b), '+/', '-_'), '='); }

function bilet(string $kimlik): string {
    $v = time();
    $govde = b64("v1|$kimlik|$v|" . ($v + BILET_OMUR) . '|' . b64(random_bytes(16)));
    return $govde . '.' . b64(hash_hmac('sha256', $govde, ayar()['bilet_sir'], true));
}

// ---------- kişi silme (kullanıcı isteğiyle ya da yönetici komutuyla) ----------
function kisi_sil(string $eposta_ozet): int {
    $s = db()->prepare('SELECT id FROM deneme_kisi WHERE eposta_ozet = ?');
    $s->execute([$eposta_ozet]);
    $n = 0;
    foreach ($s->fetchAll() as $r) {
        db()->prepare('DELETE FROM deneme_oturum WHERE kisi_id = ?')->execute([$r['id']]);
        db()->prepare('DELETE FROM deneme_kisi WHERE id = ?')->execute([$r['id']]);
        $n++;
    }
    db()->prepare('DELETE FROM deneme_kod WHERE eposta_ozet = ?')->execute([$eposta_ozet]);
    return $n;
}

// ---------- e-posta gönderimi: kimlik doğrulamalı SMTP (ssl:// 465 ya da STARTTLS 587) ----------
function posta_gonder(string $alici, string $konu, string $govde): bool {
    $a = ayar();
    if (!eposta_gecerli($alici)) { return false; }
    // yanıtlar info@'ya (no-reply'a yazılan yanıt kaybolmasın). Değer YALNIZ ayardan / sabitten, kullanıcı girdisinden
    // asla; adres doğrulanır (CR/LF ve geçersiz adres başlığa giremez). From ve zarf göndereni (MAIL FROM) değişmez (SPF / DKIM).
    $yanit = (string)($a['posta_yanit'] ?? 'info@odyobuk.com');
    if (!eposta_gecerli($yanit)) { $yanit = ''; }
    if (($a['posta'] ?? 'smtp') === 'dosya') {                       // yalnız yerel deneme: diske yaz
        file_put_contents($a['posta_dosya'], json_encode(['alici' => $alici, 'konu' => $konu, 'govde' => $govde, 'yanit' => $yanit]) . "\n", FILE_APPEND);
        return true;
    }
    $host = $a['smtp_sunucu']; $port = (int)($a['smtp_port'] ?? 465);
    $ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $hedef = ($port === 465 ? 'ssl://' : 'tcp://') . $host . ':' . $port;
    $s = @stream_socket_client($hedef, $no, $hata, 15, STREAM_CLIENT_CONNECT, $ctx);
    if (!$s) { error_log("odyobuk-deneme: smtp bağlanamadı ($no)"); return false; }
    stream_set_timeout($s, 15);
    $oku = function () use ($s): string { $t = ''; while (($l = fgets($s, 1024)) !== false) { $t .= $l; if (strlen($l) < 4 || $l[3] === ' ') { break; } } return $t; };
    $yaz = function (string $k, string $bek) use ($s, $oku): bool {
        if ($k !== '') { fwrite($s, $k . "\r\n"); }
        $y = $oku(); if (strncmp($y, $bek, 3) !== 0) { error_log('odyobuk-deneme: smtp ' . substr($y, 0, 3)); return false; } return true; };
    $ad = gethostname() ?: 'odyobuk.com';
    $ok = $yaz('', '220') && $yaz("EHLO $ad", '250');
    if ($ok && $port !== 465) {
        $ok = $yaz('STARTTLS', '220') && stream_socket_enable_crypto($s, true, STREAM_CRYPTO_METHOD_TLS_CLIENT) && $yaz("EHLO $ad", '250');
    }
    $kimden = $a['posta_kimden'];
    $ok = $ok && $yaz('AUTH LOGIN', '334') && $yaz(base64_encode($a['smtp_kullanici']), '334') && $yaz(base64_encode($a['smtp_sifre']), '235')
        && $yaz("MAIL FROM:<$kimden>", '250') && $yaz("RCPT TO:<$alici>", '250') && $yaz('DATA', '354');
    if ($ok) {
        $basliklar = [
            'From: ' . mb_encode_mimeheader($a['posta_ad'] ?? 'Odyobuk Studio', 'UTF-8') . " <$kimden>",
            "To: <$alici>", 'Subject: ' . mb_encode_mimeheader($konu, 'UTF-8'), 'Date: ' . date('r'),
            ...($yanit !== '' ? ['Reply-To: ' . mb_encode_mimeheader($a['posta_ad'] ?? 'Odyobuk Studio', 'UTF-8') . " <$yanit>"] : []),
            'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . substr(strrchr($kimden, '@'), 1) . '>',
            'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64'];
        $veri = implode("\r\n", $basliklar) . "\r\n\r\n" . chunk_split(base64_encode($govde));
        $ok = $yaz($veri . "\r\n.", '250');
    }
    @fwrite($s, "QUIT\r\n"); fclose($s);
    return $ok;
}

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
