<?php
// odyobuk.com/dene: e-posta doğrulaması → deneme bileti → studio.odyobuk.com/dene. Tasarım: tasarim/DENEME_EPOSTA.md.
// Stüdyo e-posta adresini hiç görmez: bilette yalnız opak kimlik (e-postanın tuzla özeti) var.
declare(strict_types=1);
require __DIR__ . '/ortak.php';

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
// strict-origin: no-referrer'da tarayıcı stüdyoya giden form POST'unda «Origin: null» yollar, stüdyo da null'u reddeder
header('Referrer-Policy: strict-origin');
header('Cache-Control: no-store');
$studio = rtrim(ayar()['studio_url'], '/');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
     . "img-src 'self' data:; form-action 'self' $studio; frame-ancestors 'none'; base-uri 'none'");

temizle();
$adim = $_POST['adim'] ?? '';
$ip = istemci_ip();
$eposta_oz = fn(string $norm): string => ozet(ayar()['ozet_tuzu'], 'e|' . $norm);
$ileti = ''; $hata = ''; $gorunum = 'eposta'; $eposta_goster = ''; $bilet = ''; $soru = '';
$kisi = oturum_kisi();
if ($kisi) { $gorunum = 'hazir'; }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_dogru()) { $hata = 'Sayfanın süresi doldu; yeniden deneyin.'; $gorunum = $kisi ? 'hazir' : 'eposta'; }

    elseif ($adim === 'kod_iste') {
        $ham = (string)($_POST['eposta'] ?? '');
        $norm = eposta_norm($ham);
        if (!eposta_gecerli($ham) || !eposta_gecerli($norm)) { $hata = 'Geçerli bir e-posta adresi yazın.'; }
        elseif (empty($_POST['kvkk'])) { $hata = 'Devam etmek için aydınlatma metnini onaylayın.'; }
        else {
            $oz = $eposta_oz($norm);
            $eposta_goster = $ham;
            // Kod hakkı sınırsız, kitlenme yok. Kötüye kullanıma karşı: her POST önce IP başına istek
            // sayacına düşer (tek IP uçları dövemesin); sonra haklar ATOMİK olarak SIRAYLA ayrılır (eş zamanlı istekler
            // hiçbir sınırı birlikte atlayamaz); bir sonraki reddederse ya da gönderim başarısız olursa ayrılanlar geri verilir.
            // Genel tavan (herkesi etkileyen) EN SON, yalnız gerçekten gönderilecekken düşülür.
            if (!hiz('kod_istek_ip', $ip, 3600, 60)) {
                $hata = 'Bu internet bağlantısından çok istek geldi; bir saat sonra yeniden deneyin ya da info@odyobuk.com\'a yazın.';
                goto bitti;
            }
            $ayrilan = [];                                   // [tur, anahtar, pencere]
            $geri = function () use (&$ayrilan, $oz): void {
                foreach ($ayrilan as [$t, $a, $p]) { if ($t === 'kv') { kv_sil($a); } else { sayac_geri($t, $a, $p); } }
                $ayrilan = [];
            };
            //  1) aynı adrese iki gönderim arası en az 60 sn (kod ekranında geri sayım)
            $ara = (int)(ayar()['kod_arasi_sn'] ?? 60);
            if ($ara > 0) {
                if (!kv_al('kod_son|' . $oz, $ara)) {
                    $son = kv_oku('kod_son|' . $oz); $bekle = $son ? max(1, $son[1] - time()) : $ara; $gorunum = 'kod';
                    $hata = "Yeni kod için $bekle sn bekleyin; son gönderdiğimiz kod hâlâ geçerli.";
                    goto bitti;
                }
                $ayrilan[] = ['kv', 'kod_son|' . $oz, 0];
            }
            //  2) 15 dk'da 3'ten sonra doğrulama sorusu (çereze bağlı, tek kullanım, 5 dk)
            if (hiz('kod_e15', $oz, 900, 3)) { $ayrilan[] = ['kod_e15', $oz, 900]; }
            else {
                if (!isset($_POST['dogrulama']) || !soru_dogru((string)$_POST['dogrulama'])) {
                    if (isset($_POST['dogrulama'])) { $hata = 'Yanıt yanlış ya da süresi doldu; yeni soruyu yanıtlayın.'; }
                    $geri(); $soru = soru_uret(); $gorunum = 'soru'; goto bitti;
                }
                hiz('kod_e15', $oz, 900, 100000); $ayrilan[] = ['kod_e15', $oz, 900];
            }
            //  3) adres başına günde 20, 4) IP (/64) başına saatte 10, 5) genel saatte 200 — hepsi atomik
            if (!hiz('kod_egun', $oz, 86400, 20)) {
                $geri(); $hata = 'Bugün bu adrese çok kod gönderildi; yarın yeniden deneyin ya da info@odyobuk.com\'a yazın.';
                goto bitti;
            }
            $ayrilan[] = ['kod_egun', $oz, 86400];
            if (!hiz('kod_ip', $ip, 3600, 10)) {
                $geri(); $hata = 'Bu internet bağlantısından çok kod istendi; bir saat sonra yeniden deneyin ya da info@odyobuk.com\'a yazın.';
                goto bitti;
            }
            $ayrilan[] = ['kod_ip', $ip, 3600];
            if (!hiz('kod_genel', 'hepsi', 3600, (int)(ayar()['saatlik_posta_tavani'] ?? 200))) {
                $geri(); $hata = 'Şu an çok yoğunuz; birkaç dakika sonra yeniden deneyin.';
                goto bitti;
            }
            $ayrilan[] = ['kod_genel', 'hepsi', 3600];
            // kod, onu isteyen tarayıcıya bağlanır: doğrulama yalnız bu çerezle (başkası başkasının adresine tahmin yollayamaz).
            // Çerez yalnız kod gerçekten gönderilince yenilenir (önceki geçerli kod boşuna ölmesin).
            $tarayici = b64(random_bytes(24));
            $kod = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            $govde = "Merhaba,\n\nOdyobuk Studio doğrulama kodunuz:\n\n    $kod\n\nKodu odyobuk.com/dene sayfasına yazın; hesabınızı açabilir ya da şifrenizi yenileyebilirsiniz. "
                   . "10 dakika geçerlidir.\n\nBu isteği siz yapmadıysanız bu e-postayı yok sayabilirsiniz.\n\n"
                   . "Odyobuk Studio · Bir Seslendirme Evi ürünü\nhttps://odyobuk.com\n";
            if (!posta_gonder($ham, "Odyobuk Studio doğrulama kodunuz: $kod", $govde)) {
                error_log('odyobuk-deneme: kod gönderilemedi');
                $geri();                                     // hiçbir hak sayılmaz, 60 sn kilidi de kalkar
                $hata = 'Kod gönderilemedi; birkaç dakika sonra yeniden deneyin.';     // hak sayılmaz, eski kod geçerli kalır
                $gorunum = 'eposta';
                goto bitti;
            }
            // yalnız BU tarayıcının eski kodu ve süresi dolanlar silinir: başka tarayıcıdan aynı adrese istek, elinizdeki
            // geçerli kodu öldürmez (kod zaten tarayıcı çerezine bağlı)
            $eski_t = ozet(ayar()['ozet_tuzu'], 't|' . (string)($_COOKIE['od_kod'] ?? ''));
            db()->prepare('DELETE FROM deneme_kod WHERE eposta_ozet = ? AND (tarayici_ozet = ? OR bitis < ?)')->execute([$oz, $eski_t, time()]);
            db()->prepare('INSERT INTO deneme_kod (eposta_ozet, kod_ozet, tarayici_ozet, bitis, yanlis, olusturma) VALUES (?, ?, ?, ?, 0, ?)')
                ->execute([$oz, ozet(ayar()['kod_biberi'], $kod), ozet(ayar()['ozet_tuzu'], 't|' . $tarayici), time() + KOD_OMUR, time()]);
            setcookie('od_kod', $tarayici, ['path' => '/dene', 'secure' => guvenli(), 'httponly' => true, 'samesite' => 'Strict']);
            setcookie('od_duyuru', empty($_POST['duyuru']) ? '0' : '1', ['path' => '/dene', 'secure' => guvenli(), 'httponly' => true, 'samesite' => 'Strict']);
            $ileti = '';   // kod ekranı kendi iletisini gösterir (adres + spam notu)
            $gorunum = 'kod'; $eposta_goster = $ham;
        }
    }

    elseif ($adim === 'kod_dogrula') {
        $ham = (string)($_POST['eposta'] ?? ''); $norm = eposta_norm($ham);
        $kod = preg_replace('/\D/', '', (string)($_POST['kod'] ?? ''));
        $eposta_goster = $ham; $gorunum = 'kod';
        if (!hiz('dogrula_ip', $ip, 3600, 20)) { $hata = 'Çok fazla deneme yapıldı; bir süre sonra yeniden deneyin.'; }
        elseif (!eposta_gecerli($norm) || strlen($kod) !== 6) { $hata = 'Kod yanlış ya da süresi dolmuş.'; }
        else {
            $oz = $eposta_oz($norm);
            $tz = ozet(ayar()['ozet_tuzu'], 't|' . (string)($_COOKIE['od_kod'] ?? ''));
            $s = db()->prepare('SELECT * FROM deneme_kod WHERE eposta_ozet = ? AND tarayici_ozet = ? AND bitis > ? ORDER BY id DESC LIMIT 1');
            $s->execute([$oz, $tz, time()]);
            $k = $s->fetch();
            // deneme hakkı önce ATOMİK olarak düşülür (eş zamanlı tahminler 5 sınırını aşamasın), sonra karşılaştırılır
            $hak = false;
            if ($k) {
                $u = db()->prepare('UPDATE deneme_kod SET yanlis = yanlis + 1 WHERE id = ? AND yanlis < ?');
                $u->execute([$k['id'], KOD_YANLIS]);
                $hak = $u->rowCount() === 1;
            }
            // Adres çapında saatlik yanlış kilidi YOK (başkası kendi tarayıcısından yanlış girerek kurbanın
            // adresini kilitleyemesin). Tahmini sınırlayan: kod başına 5 atomik hak + adres başına günde 20 kod + IP sınırları.
            if (!$k || !$hak) { $hata = 'Kod yanlış ya da süresi dolmuş. Yeni kod isteyin.'; }
            elseif (!hash_equals($k['kod_ozet'], ozet(ayar()['kod_biberi'], $kod))) {
                $hata = 'Kod yanlış ya da süresi dolmuş.';
            } else {
                db()->prepare('DELETE FROM deneme_kod WHERE eposta_ozet = ?')->execute([$oz]);
                $s = db()->prepare('SELECT * FROM deneme_kisi WHERE eposta_ozet = ?'); $s->execute([$oz]);
                $var = $s->fetch();
                $duyuru = ($_COOKIE['od_duyuru'] ?? '0') === '1' ? 1 : 0;
                if ($var) {
                    db()->prepare('UPDATE deneme_kisi SET dogrulama = ?, kvkk_onay = ?, duyuru_onay = ? WHERE id = ?')
                        ->execute([time(), time(), max($duyuru, (int)$var['duyuru_onay']), $var['id']]);
                    $kid = (int)$var['id'];
                } else {
                    try {
                        db()->prepare('INSERT INTO deneme_kisi (eposta, eposta_ozet, kimlik, dogrulama, kvkk_onay, duyuru_onay, deneme_sayisi, olusturma)
                            VALUES (?, ?, ?, ?, ?, ?, 0, ?)')->execute([$norm, $oz, kimlik($norm), time(), time(), $duyuru, time()]);
                        $kid = (int)db()->lastInsertId();
                    } catch (PDOException $e) {        // eş zamanlı iki doğrulama: öbürü kaydı açmış
                        $s = db()->prepare('SELECT id FROM deneme_kisi WHERE eposta_ozet = ?'); $s->execute([$oz]);
                        $kid = (int)($s->fetch()['id'] ?? 0);
                        if (!$kid) { throw $e; }
                    }
                }
                oturum_ac($kid);
                // doğrulanınca doğrudan Studio'nun kayıt sayfasına (hesap aç / şifre yenile); bilet kimlik başına sınırlı
                if (hiz('bilet_k1', kimlik($norm), 60, 3) && hiz('bilet_k60', kimlik($norm), 3600, 20)) {
                    $bilet = bilet(kimlik($norm)); $gorunum = 'git'; goto bitti;
                }
                header('Location: /dene/', true, 303);
                exit;
            }
        }
    }

    elseif ($adim === 'bilet' && $kisi) {
        // kimlik başına dakikada 3 / saatte 20 bilet
        if (!hiz('bilet_k1', $kisi['kimlik'], 60, 3) || !hiz('bilet_k60', $kisi['kimlik'], 3600, 20)) {
            $hata = 'Çok sık istek yapıldı; bir dakika sonra yeniden deneyin.'; $gorunum = 'hazir';
        } else {
            db()->prepare('UPDATE deneme_kisi SET son_deneme = ?, deneme_sayisi = deneme_sayisi + 1 WHERE id = ?')->execute([time(), $kisi['id']]);
            $bilet = bilet($kisi['kimlik']); $gorunum = 'git';
        }
    }

    elseif ($adim === 'cikis') { oturum_kapat(); $kisi = null; $gorunum = 'eposta'; $ileti = 'Bu tarayıcıdaki oturum kapatıldı.'; }

    elseif ($adim === 'sil' && $kisi) {
        // kullanıcı isteğiyle silme: oturum e-postanın sahibi olduğunu zaten kanıtladı (son 30 günde kodla doğrulandı)
        kisi_sil($kisi['eposta_ozet']); oturum_kapat(); $kisi = null; $gorunum = 'eposta';
        $ileti = 'E-posta adresiniz ve doğrulama kayıtlarınız silindi.';
    }
}
bitti:
$csrf = csrf();
?><!doctype html>
<html lang="tr" data-tema="sepya">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,viewport-fit=cover">
<title>Ücretsiz hesap — Odyobuk Studio</title>
<link rel="icon" type="image/png" sizes="96x96" href="/simge-96.png">
<link rel="apple-touch-icon" href="/simge-180.png">
<style>
html{touch-action:pan-x pan-y}      /* telefonda iki parmakla yakınlaştırma kapalı (giriş ekranıyla aynı) */
/* odyobuk.com dili: Newsreader başlık, logo renk geçişi; temalar Beyaz · Sepya · Koyu (tanitim/site/index.html ile aynı) */
@font-face{font-family:'Newsreader';font-style:normal;font-weight:400 600;font-display:swap;src:url(/fonts/newsreader-latin.woff2) format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
@font-face{font-family:'Newsreader';font-style:normal;font-weight:400 600;font-display:swap;src:url(/fonts/newsreader-latinext.woff2) format('woff2');unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C4,U+2113,U+2C60-2C7F,U+A720-A7FF}
:root{--bg:#fff;--bg2:#f4f6fb;--card:#fff;--line:#e6e9f1;--line2:#d3d7e4;--text:#14162a;--muted:#5b6078;--soft:#8a8fa6;--input:#fff;
  --c1:#00c6ff;--c2:#1f3cff;--c3:#7a2cf0;--grad:linear-gradient(120deg,var(--c1) 0%,var(--c2) 52%,var(--c3) 100%);
  --err:#d63c52;--errbg:#fdeef0;--ok:#21a46b;--okbg:#e8f6ef;
  --serif:"Newsreader",ui-serif,"Iowan Old Style",Georgia,serif;--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}
:root[data-tema="sepya"]{--bg:#f6efe2;--bg2:#efe6d4;--card:#fbf7ee;--line:#e4d8c1;--line2:#d3c3a5;--text:#2e2418;--muted:#6b5b46;--soft:#95836a;--input:#fffdf8;--okbg:#e6efd9}
:root[data-tema="koyu"]{--logo-yay:#5b8cff;--bg:#0d0e18;--bg2:#141626;--card:#171a2c;--line:#252a40;--line2:#323852;--text:#eef0fa;--muted:#a6abc4;--soft:#7d8299;--input:#11131f;
  --errbg:#3a1820;--err:#ff7a8c;--okbg:#12301f;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--bg);color:var(--text);font:16px/1.55 var(--sans);-webkit-font-smoothing:antialiased;position:relative;overflow-x:hidden}
body:before{content:"";position:fixed;left:50%;top:-140px;width:900px;height:620px;transform:translateX(-50%);background:radial-gradient(closest-side,color-mix(in srgb,var(--c2) 12%,transparent),transparent);z-index:-1;pointer-events:none}
a{color:inherit}
.ust{display:flex;align-items:center;justify-content:space-between;padding:20px 28px}
.ust a{font-size:14px;color:var(--muted);text-decoration:none}.ust a:hover{color:var(--text)}
main{flex:1;width:min(440px,100%);margin:0 auto;padding:4vh 16px 40px}
.marka{text-align:center;margin-bottom:22px}
.marka img,.marka .logo-svg{width:56px;height:56px;display:block;margin:0 auto 12px;filter:drop-shadow(0 10px 22px rgba(31,60,255,.25))}
h1{font-family:var(--serif);font-weight:500;font-size:30px;letter-spacing:-.01em;margin:0;line-height:1.15}
.alt{margin:6px 0 0;color:var(--muted);font-size:15px}
.adimlar{display:flex;justify-content:center;gap:6px;margin:16px 0 0;padding:0;list-style:none;font-size:12.5px;color:var(--soft)}
.adimlar li{display:flex;align-items:center;gap:6px}.adimlar li+li:before{content:"";width:18px;height:1px;background:var(--line2)}
.adimlar b{width:20px;height:20px;border-radius:50%;display:grid;place-items:center;font-size:11px;border:1px solid var(--line2);color:var(--soft);font-weight:600}
.adimlar .on{color:var(--text)}.adimlar .on b{background:var(--grad);border:0;color:#fff}
.adimlar .bitti b{background:var(--ok);border:0;color:#fff}
.kart{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:26px;display:flex;flex-direction:column;gap:16px;
  box-shadow:0 1px 2px rgba(20,22,42,.04),0 24px 48px -28px rgba(31,60,255,.28)}
form{display:flex;flex-direction:column;gap:16px;margin:0}
label{display:flex;flex-direction:column;gap:7px;font-size:13.5px;font-weight:500;color:var(--muted)}
input[type=email],input[type=text]{font:inherit;font-size:16px;color:var(--text);background:var(--input);border:1px solid var(--line2);border-radius:11px;padding:12px 14px;width:100%}
input:focus{outline:none;border-color:var(--c2);box-shadow:0 0 0 4px color-mix(in srgb,var(--c2) 14%,transparent)}
input.kod{font-size:26px;letter-spacing:.5em;text-align:center;font-variant-numeric:tabular-nums;padding:12px 0 12px .5em}
.onay{flex-direction:row;align-items:flex-start;gap:10px;font-weight:400;font-size:13.5px;line-height:1.45}
.onay input{margin:2px 0 0;width:17px;height:17px;flex:none;accent-color:var(--c2)}
.onay a{color:var(--c2)}
button.ana{font:600 16px var(--sans);color:#fff;background:var(--grad);border:0;border-radius:12px;padding:13px 16px;cursor:pointer;box-shadow:0 10px 22px -12px rgba(31,60,255,.7)}
button.ana:hover{filter:brightness(1.08)}
button.ikinci{font:500 13.5px var(--sans);color:var(--muted);background:none;border:0;cursor:pointer;text-decoration:underline;text-underline-offset:3px;padding:0}
button.ikinci:hover{color:var(--text)}
button.ikinci:disabled{opacity:.55;cursor:default;text-decoration:none}
.hata{color:var(--err);background:var(--errbg);border-radius:10px;padding:9px 12px;font-size:14px}
.ileti{color:var(--muted);font-size:14px;line-height:1.5}
.ileti.ok{color:var(--text);background:var(--okbg);border-radius:10px;padding:10px 12px}
.ileti b{color:var(--text)}
.satir{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
.not{display:flex;gap:10px;align-items:flex-start;color:var(--muted);font-size:13px;line-height:1.5;margin:20px 4px 0}
.not svg{flex:none;margin-top:2px;color:var(--c2)}
.beta{text-align:center;color:var(--soft);font-size:12.5px;margin-top:14px}
footer{text-align:center;color:var(--soft);font-size:12.5px;padding:18px}
</style>
</head>
<body>
<div class="ust"><a href="/">← odyobuk.com</a></div>
<main>
<?php $adimno = $gorunum === 'eposta' ? 1 : ($gorunum === 'kod' ? 2 : 3); ?>
<div class="marka">
  <svg class="logo-svg" xmlns="http://www.w3.org/2000/svg" viewBox="100 95 1350 1350" role="img" aria-label="Odyobuk"><defs><linearGradient id="ob" gradientUnits="userSpaceOnUse" x1="738.37" y1="1431.94" x2="1436.62" y2="733.69"><stop offset="0" stop-color="#2ae1ee"/><stop offset=".5" stop-color="#2361fc"/><stop offset="1" stop-color="#aa28fc"/></linearGradient><linearGradient id="ok" gradientUnits="userSpaceOnUse" x1="738.37" y1="1152.94" x2="1157.62" y2="733.69"><stop offset="0" stop-color="#9a27fb"/><stop offset=".5" stop-color="#4056fc"/><stop offset="1" stop-color="#1cf4f3"/></linearGradient></defs><path fill="var(--logo-yay,#094bb5)" d="M 880.96875 589.335938 L 856.359375 613.945312 C 790.855469 548.441406 684.101562 548.265625 618.421875 613.945312 C 552.738281 679.625 552.917969 786.378906 618.421875 851.882812 L 593.8125 876.492188 C 514.675781 797.355469 514.675781 668.472656 593.8125 589.335938 C 672.949219 510.203125 801.832031 510.203125 880.96875 589.335938 Z M 533.972656 529.5 C 421.730469 641.742188 421.730469 824.089844 533.972656 936.332031 L 558.582031 911.722656 C 459.972656 813.113281 459.972656 652.71875 558.582031 554.105469 C 657.191406 455.496094 817.585938 455.496094 916.199219 554.105469 L 940.804688 529.5 C 828.5625 417.257812 646.214844 417.257812 533.972656 529.5 Z M 474.136719 469.660156 C 328.964844 614.832031 328.964844 851 474.136719 996.167969 L 498.742188 971.5625 C 367.203125 840.023438 367.203125 626.160156 498.742188 494.621094 C 630.28125 363.082031 844.320312 362.90625 975.859375 494.445312 L 1000.46875 469.835938 C 855.472656 324.488281 619.304688 324.488281 474.136719 469.660156 Z M 414.296875 409.820312 C 236.195312 587.921875 236.195312 877.910156 414.296875 1056.007812 L 438.90625 1031.398438 C 274.4375 866.933594 274.4375 599.25 438.90625 434.785156 C 603.371094 270.316406 871.054688 270.316406 1035.519531 434.785156 L 1060.128906 410.175781 C 882.382812 231.722656 592.394531 231.722656 414.296875 409.820312 Z M 737.390625 191.535156 C 592.925781 191.535156 456.960938 247.832031 354.632812 350.160156 C 252.308594 452.488281 196.007812 588.453125 196.007812 732.914062 C 196.007812 877.378906 252.308594 1013.34375 354.632812 1115.667969 L 379.242188 1091.0625 C 181.847656 893.664062 181.667969 572.34375 379.242188 374.769531 C 576.816406 177.195312 898.140625 177.371094 1095.535156 374.769531 L 1120.144531 350.160156 C 1017.816406 247.832031 881.851562 191.535156 737.390625 191.535156 Z M 737.390625 106.910156 C 570.265625 106.910156 413.058594 172.058594 294.796875 290.320312 C 176.535156 408.582031 111.386719 565.792969 111.386719 732.914062 C 111.386719 900.039062 176.535156 1057.246094 294.796875 1175.507812 L 319.402344 1150.898438 C 207.695312 1039.191406 146.4375 890.832031 146.261719 733.09375 C 146.4375 574.996094 207.695312 426.640625 319.402344 314.929688 C 431.113281 203.21875 579.472656 141.964844 737.210938 141.785156 C 895.128906 141.785156 1043.488281 203.394531 1155.019531 314.929688 L 1179.804688 290.144531 C 1061.722656 172.058594 904.511719 106.910156 737.390625 106.910156 Z M 737.390625 106.910156 "/><path fill="url(#ob)" d="M1436.62 733.69A698.25 698.25 0 0 1 738.37 1431.94L738.37 1219.93A486.24 486.24 0 0 0 1224.61 733.69Z"/><path fill="url(#ok)" d="M1157.62 733.69A419.25 419.25 0 0 1 738.37 1152.94L738.37 960.47A226.78 226.78 0 0 0 965.15 733.69Z"/></svg>
  <h1>Ücretsiz hesap</h1>
  <p class="alt">Ücretsiz · kurulum yok</p>
  <p class="alt" style="font-size:13px;margin-top:-4px">Hesabınız varsa aynı adımlarla şifrenizi yenilersiniz.</p>
  <ol class="adimlar" aria-label="Adımlar">
    <li class="<?= $adimno === 1 ? 'on' : 'bitti' ?>"><b><?= $adimno > 1 ? '✓' : '1' ?></b>E-posta</li>
    <li class="<?= $adimno === 2 ? 'on' : ($adimno > 2 ? 'bitti' : '') ?>"><b><?= $adimno > 2 ? '✓' : '2' ?></b>Kod</li>
    <li class="<?= $adimno === 3 ? 'on' : '' ?>"><b>3</b>Hesap</li>
  </ol>
</div>
<div class="kart">
<?php if ($hata): ?><div class="hata" role="alert"><?= h($hata) ?></div><?php endif; ?>
<?php if ($ileti): ?><div class="ileti"><?= h($ileti) ?></div><?php endif; ?>

<?php if ($gorunum === 'git'): ?>
  <div class="ileti">Studio açılıyor…</div>
  <form method="post" action="<?= h($studio) ?>/kaydol/bilet" id="git">
    <input type="hidden" name="bilet" value="<?= h($bilet) ?>">
    <button class="ana" type="submit">Devam et</button>
  </form>
  <script>document.getElementById("git").submit();</script>

<?php elseif ($gorunum === 'hazir'): ?>
  <div class="ileti ok">E-postanız doğrulandı. Hesabınızı açmak ya da şifrenizi yenilemek için devam edin; bu tarayıcı 30 gün hatırlanır.</div>
  <form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="adim" value="bilet">
    <button class="ana" type="submit">Devam et</button></form>
  <div class="satir">
    <form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="adim" value="cikis">
      <button class="ikinci" type="submit">Bu tarayıcıda oturumu kapat</button></form>
    <form method="post" onsubmit="return confirm('E-posta adresiniz ve doğrulama kayıtlarınız kalıcı olarak silinsin mi?')">
      <input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="adim" value="sil">
      <button class="ikinci" type="submit">E-postamı ve kayıtlarımı sil</button></form>
  </div>

<?php elseif ($gorunum === 'kod'): ?>
  <div class="ileti">Kod gönderildi: <b><?= h($eposta_goster) ?></b> adresine 6 haneli bir kod yolladık. Birkaç dakika
    içinde gelmezse istenmeyen (spam) klasörüne bakın. Bu tarayıcıdan birden çok kez istediyseniz yalnız en son gelen kod geçerlidir.</div>
  <form method="post">
    <input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="adim" value="kod_dogrula">
    <input type="hidden" name="eposta" value="<?= h($eposta_goster) ?>">
    <label>Doğrulama kodu<input class="kod" type="text" name="kod" inputmode="numeric" autocomplete="one-time-code" maxlength="7" placeholder="••••••" required autofocus></label>
    <button class="ana" type="submit">Doğrula</button>
  </form>
<?php $bk = ($x = kv_oku('kod_son|' . $eposta_oz(eposta_norm($eposta_goster)))) ? max(0, $x[1] - time()) : 0; ?>
  <form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="adim" value="kod_iste">
    <input type="hidden" name="eposta" value="<?= h($eposta_goster) ?>"><input type="hidden" name="kvkk" value="1">
    <input type="hidden" name="duyuru" value="<?= ($_COOKIE['od_duyuru'] ?? '0') === '1' ? '1' : '' ?>">
    <button class="ikinci" type="submit" id="yeniden" data-kalan="<?= (int)$bk ?>">Kodu yeniden gönder</button></form>
  <form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><button class="ikinci" type="submit">Başka bir e-posta yaz</button></form>
  <script>(function () { const b = document.getElementById("yeniden"); let k = +b.dataset.kalan;
    const yaz = () => { b.disabled = k > 0; b.textContent = k > 0 ? `Kodu yeniden gönder (${k})` : "Kodu yeniden gönder"; };
    yaz(); if (k > 0) { const t = setInterval(() => { k--; yaz(); if (k <= 0) clearInterval(t); }, 1000); } })();</script>

<?php elseif ($gorunum === 'soru'): ?>
  <div class="ileti">Bu adrese kısa sürede birkaç kod gönderdik. Yeni kod için kısa bir doğrulama:</div>
  <form method="post">
    <input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="adim" value="kod_iste">
    <input type="hidden" name="eposta" value="<?= h($eposta_goster) ?>"><input type="hidden" name="kvkk" value="1">
    <input type="hidden" name="duyuru" value="<?= ($_COOKIE['od_duyuru'] ?? '0') === '1' ? '1' : '' ?>">
    <label>Doğrulama: <?= h($soru) ?> = ?<input type="text" name="dogrulama" inputmode="numeric" maxlength="3" autocomplete="off" required autofocus></label>
    <button class="ana" type="submit">Kodu yeniden gönder</button>
  </form>

<?php else: ?>
  <form method="post">
    <input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="adim" value="kod_iste">
    <label>E-posta adresiniz<input type="email" name="eposta" autocomplete="email" maxlength="254" placeholder="ornek@eposta.com" required autofocus></label>
    <label class="onay"><input type="checkbox" name="kvkk" value="1" required><span>E-posta adresimin hesap açmak ve şifremi yenilemek için işlenmesine ilişkin
      <a href="/aydinlatma.html" target="_blank" rel="noopener">aydınlatma metnini</a> okudum.</span></label>
    <label class="onay"><input type="checkbox" name="duyuru" value="1"><span>Odyobuk Studio duyurularını e-postayla almak
      istiyorum. <span style="color:var(--soft)">(isteğe bağlı)</span></span></label>
    <button class="ana" type="submit">Kod gönder</button>
  </form>
<?php endif; ?>
</div>
<p class="not"><svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="7" width="10" height="7" rx="2"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/></svg>
  <span>E-posta adresiniz yalnız Seslendirme Evi'nin kayıtlarında tutulur; ses ve metninizin işlendiği Studio
  sunucusuna gönderilmez. Dilediğinizde «E-postamı ve kayıtlarımı sil» ile silebilirsiniz.</span></p>
<p class="beta">Odyobuk Studio şu an beta sürümünde · dakika ve paket satın alma yakında</p>
</main>
<footer>© 2026 Odyobuk Studio · Bir Seslendirme Evi ürünü</footer>
</body>
</html>
