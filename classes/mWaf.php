<?php
class mWaf {
    private $blacklist = array();
    // İstek sayısı sınırı
    private $requestLimit = 100;
    // İstek sayacı
    private $requestCounter = array();
    //
    private $debug = false;

    public function __construct() {
        if($this->debug) {
            error_reporting(E_ALL);
        } else {
            error_reporting(0);
        }
        // Waf sınıfının yapılandırıcı fonksiyonu
        // Burada, sınıfın özelliklerini ve gerekli başlangıç işlemlerini yapabilirsiniz
    }

    public function startProtection() 
    {
        $this->logRequest();
        $this->filterXss();
        $this->filterSqlInjection();
        $this->protectDdos();
    }

    public function filterXss()
    {
        // POST ve GET parametrelerini dizi olarak al
        $post = $_POST;
        $get = $_GET;
    
        // Her bir POST ve GET parametresini dolaş
        foreach ($post as $key => $value) {
            // POST parametresini geçersiz HTML karakterlerinden temizle
            $post[$key] = htmlspecialchars($value);
        }
    
        foreach ($get as $key => $value) {
            // GET parametresini geçersiz HTML karakterlerinden temizle
            $get[$key] = htmlspecialchars($value);
        }
    
        // Temizlenmiş POST ve GET parametrelerini tekrar ata
        $_POST = $post;
        $_GET = $get;
        $this->logRequest();
    }
    
    public function filterSqlInjection()
    {
        // POST ve GET parametrelerini dizi olarak al
        $post = $_POST;
        $get = $_GET;
    
        // Her bir POST ve GET parametresini dolaş
        foreach ($post as $key => $value) {
            // POST parametresini sql injection saldırılarından koruma altına al
            $post[$key] = addslashes($value);
        }
    
        foreach ($get as $key => $value) {
            // GET parametresini sql injection saldırılarından koruma altına al
            $get[$key] = addslashes($value);
        }
    
        // Koruma altına alınmış POST ve GET parametrelerini tekrar ata
        $_POST = $post;
        $_GET = $get;
    }
    
    public function checkIpBlacklist($ip)
    {
        // Bu fonksiyon, belirtilen IP adresinin kara listede olup olmadığını kontrol eder
        return in_array($ip, $this->blacklist);
    }

    public function protectDdos()
    {
        $ip = $this->getRealIP();
        // Bu fonksiyon, ddos saldırılarına karşı koruma sağlar
        // Örneğin, belirtilen IP adresinden gelen istek sayısını kontrol ederek
        // aşırı istekleri engelleyebilirsiniz
        if (in_array($ip, $this->blacklist)) {
            return;
        }
    
        // Eğer istek sayacı dizisi içinde IP adresi bulunmuyorsa, sayacı sıfırla
        if (!isset($this->requestCounter[$ip])) {
            $this->requestCounter[$ip] = 0;
        }
    
        // İstek sayısını artır
        $this->requestCounter[$ip]++;
    
        // Eğer istek sayısı sınırını aştıysa, IP adresini kara listede ekle
        if ($this->requestCounter[$ip] > $this->requestLimit) {
            $this->blacklist[] = $ip;
        }
    }

    public function protectCsrf()
    {
        // Anahtar üret
        $key = bin2hex(random_bytes(16));
        
        // Anahtarı sakla
        $_SESSION['csrf_key'] = $key;
        
        // Forma gizli alan olarak ekle
        echo '<input type="hidden" name="csrf_key" value="' . $key . '">';
    }
    
    public function verifyCsrf()
    {
        // Formdan gelen anahtarı al
        $key = $_POST['csrf_key'];
        
        // Kaydedilen anahtarla karşılaştır
        if (!isset($_SESSION['csrf_key']) || $_SESSION['csrf_key'] !== $key) {
            // Anahtarlar eşleşmezse hata mesajı göster veya yönlendirme yap
            header('Location: /error.php');
            exit;
        }
        
        // Anahtar doğrulandı, artık kullanılabilir
        unset($_SESSION['csrf_key']);
    }

    public function logRequest()
    {
        // Log dosyasının adı ve yolu
        $logFile = 'mwaf.log';
    
        // Log formatı
        $logFormat = "[%s] %s %s %s\n";
    
        $ip = $this->getRealIP();
    
        $url = $_SERVER['REQUEST_URI'];
    
        $type = $_SERVER['REQUEST_METHOD'];

        $timestamp = time();

        // İşlem tarihini biçimlendir
        $date = date('Y-m-d H:i:s', $timestamp);

        // İşlem tipini belirle (GET, POST, vs.)
        $method = $type === 'GET' ? 'GET' : 'POST';
    
        // Log dosyasına yazılacak metin
        $logText = sprintf($logFormat, $date, $ip, $method, $url);
    
        // Log dosyasına metni ekle
        file_put_contents($logFile, $logText, FILE_APPEND);
    }

    protected function getRealIP() {
        // IP adresi varsayılan olarak bilinmez olsun
        $ip = 'Unknown';
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // HTTP_X_FORWARDED_FOR header'ı varsa, IP adresini buradan al
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else if (isset($_SERVER['REMOTE_ADDR'])) {
            // HTTP_X_FORWARDED_FOR header'ı yoksa, REMOTE_ADDR header'ını kullan
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return $ip;
    }
    
    
    
}
