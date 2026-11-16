<?php
// Cloudflare'in yayımladığı adres aralıkları (https://www.cloudflare.com/ips/, 16 Kasım 2026'da bilinen liste).
// CF-Connecting-IP başlığına yalnız istek bu aralıklardan geliyorsa güvenilir. Liste değişirse bu dosya güncellenir
// (ayar.php'deki 'cloudflare_araliklari' bunu geçersiz kılar). Açık bilgi; sır değildir.
if (basename($_SERVER['SCRIPT_FILENAME'] ?? '') === 'cloudflare.php') { http_response_code(404); exit; }
return [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];
