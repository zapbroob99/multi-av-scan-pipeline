# Yönetici yapılandırması incelemesi

Tarih: 2026-11-12. İlk inceleme aşağıda korunmuştur; uygulanan parçalar bu bölümde izlenir.

2026-11-13 düzeltmesi: kullanıcının asıl önceliği görevlerin farklı menülere dağılması.
Yerleşim, tekrar ve kurulum akışlarının genel incelemesi
[ADMIN_INFORMATION_ARCHITECTURE.md](ADMIN_INFORMATION_ARCHITECTURE.md) içinde.
Yeni özellikleri genişletmeden önce ekranların esas yerini düzenlemek öneriliyor.

## Uygulama durumu

- Görev odaklı Yapılandırma merkezi ve müşteri Overview ekranı uygulandı.
- MiB etiketleri, sağlık kontrolü adı, geçersiz HTTP tavanı görünümü ve pilot/prod
  arşiv env aktarımı düzeltildi.
- Limit alanlarında ve müşteri özetinde ortak kaynak/kapsam/uygulama zamanı/yeniden
  başlatma açıklamaları var. Geçersiz veya sınırlandırılmış değerlerin fallback
  davranışı görünür; API ortamı worker ortamı gibi sunulmuyor.
- Kaydedilmiş API/ICAP profilinde yan etkisiz kural önizlemesi var. Boyut, beyan
  edilen uzantı ve ayrı seçilen header türü kullanılıyor; bilinmeyen header birden
  fazla ilk eşleşmeye yol açarsa belirsizlik gösteriliyor. Bu bir güvenlik kararı,
  dosya taraması veya kabul garantisi değil. Taslak kural denemesi henüz yok.
- Motorun hangi güncel müşteri profillerinde kullanıldığı sayfalı gösteriliyor.
  Bu ilk bağımlılık görünümü; tam pool/profil/klasör değişiklik etki analizi değil.
- Limit kaydı onayında mevcut/sonraki değer ve etki açıklaması var; değiştirilmeyen
  boyutun bayt değeri yuvarlanmıyor.

Açık: diğer yönetim alanlarına açıklama sözleşmesinin genişletilmesi, deferred ve
folder yollarının etkin davranış görünümü, kanıtlanabilir kural gölgelenmesi,
pool/profil/klasör bağımlılıkları, alan bazlı değişiklik geçmişi ve profil şablonları.
Gerçek yönetici kullanılabilirlik ölçümü ve PostgreSQL dağıtım ölçeği doğrulaması
yapılmadı. Değişiklikler yerel; yayın/kurulum doğrulaması ayrı bir aşama.

## Sonuç

Mevcut düzen yönetici açısından optimal değil. Alanların farklı nesnelere ait olması
teknik olarak doğru; aynı görevi tamamlamak için bu nesneler arasındaki ilişkileri
operatörün zihninde birleştirmesi gerekiyor. Asıl ihtiyaç daha fazla form değil,
ayarlara ortak bir anlam ve görev odaklı bir giriş noktası vermek.

Tek dev ayar sayfası veya her şeyi veritabanına taşımak önerilmiyor. Sunucu güvenlik
sınırları, müşteri politikaları ve çalışan servislerin gerçek durumu ayrı kalmalı.
Bunların etkisi birlikte açıklanmalı.

## Kapsam ve kanıt sınırı

İnceleme mevcut React ekranları, backend çözümleyicileri, pilot/üretim compose
ve örnek env dosyaları ile mimari belgelere dayanır. Canlı kurum yapılandırması,
gerçek yönetici oturumları veya kullanılabilirlik ölçümü incelenmedi. Bu çalışma
yeni bir kapsamlı güvenlik denetimi ya da yük testi değildir. Bu bölüm ilk inceleme
anını anlatır; sonraki kod değişiklikleri yukarıda listelenir.

Sayılabilir durum:

- `SYSTEM_TABS`: durum, işletim ve yapılandırmayı bir arada tutan 10 sekme.
- Müşteri dialogu: Settings, Connection, Scan profiles, Storage, Credentials.
- `scan_policy.SPECS`: tarayıcıdan düzenlenen 4 operasyonel alan.
- Aktif örnek atamalar: `.env.example` 54, `.env.pilot.example` 103,
  `.env.production.example` 95. Bunlar her yöneticinin doldurması gereken alan
  sayısı veya tüm desteklenen ayarların eksiksiz envanteri değildir.

## Mevcut sahiplik haritası

| Alan | Bugünkü yer | Değişiklik sahibi / niteliği | Yöneticiye eksik kalan bağ |
|---|---|---|---|
| API bekleme, önerilen sorgu aralığı, yükleme politikası, SIEM olay seçimi | Limits & notifications | DB override; anlık okunan operasyonel politika | API, ICAP ve motor sınırları birlikte görünmüyor |
| HTTP istek tavanı | Env/compose; politikada salt okunur bilgi | Dağıtım sınırı | Dosya boyutu ile multipart gövdesi farkı, geçersiz değer durumu |
| Müşteri kimliği, erişime açıklığı | Service clients / Settings | Müşteri kaydı | Genel Settings adı gerçekte çok dar bir kapsamı anlatıyor |
| Kural sırası, motor seçimi, arşiv davranışı, sonuçsuzluk tercihi | Müşteri / Scan profiles | Müşteri politikası | Taşıma ve motor yetenekleriyle birlikte etkisi |
| Anahtar, ICAP bağı, bağlantı hazırlığı | Credentials + Connection + ICAP ekranı + env | Karma sahiplik | Yapılandırılmış, erişilebilir ve gerçekten kullanılan ayrımı |
| Motor yapılandırması | System / Engines | Motor instance ayarı + fallback kaynakları | Worker üzerinde çözülmüş etkin değer ve kaynağı |
| Worker etiketleri, kapasitesi, taşımacılığı | Worker nodes + Pools + Engines + host config | Topoloji ve worker dağıtımı | Profil -> motor -> pool -> uygun node zinciri |
| Mantıksal depolama backend'i ve mount | Env/compose | Dağıtım | UI anahtarının gerçek worker üzerindeki kullanılabilirliği |
| Müşteri depolama yetkisi | Müşteri / Storage | Environment veya custom; custom replace eder | Yetkinin kaynağı ve folder/intake ile bağı |
| İzlenen klasör ve keşif ayarları | Müşteri / Storage; Folder scanning sonuçları | Location kaydı + worker | Profil Scan seçse bile faz 1'de full_pending kalabilmesi |
| SIEM | Olay seçimi ayrı; teslimat ICAP ile aynı ekran; endpoint/secret env | Operasyonel politika + dağıtım + outbox | Olay üretiliyor mu, worker var mı, teslimat deneniyor mu? |
| Saklama | Overview + Retention cleanup + env | Salt okunur politika; ayrıca kontrollü silme işlemi | Politika düzenleme ile temizlik çalıştırmanın ayrımı |
| Hash listesi ve istisnalar | System altında Engines yolları | Güvenlik politikası | Allowlist kaydı ile kararı değiştiren istisna arasındaki fark |

## Bulgular

### F1 — Navigasyon görevlerden çok teknik birikimi yansıtıyor

System sekmeleri worker/pool/motor konfigürasyonunu; queue/intake/delivery işletimini;
retention işlemini; hash listesi ve istisna politikasını bir araya getiriyor.
ICAP ve SIEM aynı ekranın iki farklı yönlü entegrasyonu. Sistem limitleri ise aynı
System alanının dışında Administration altında. Sorun toplam sayfadan çok, hangi
sorunun hangi sayfaya ait olduğunun tahmin edilememesi.

Kanıt: `frontend/src/components/workspace-navigation.tsx`,
`frontend/src/components/section-tabs.tsx:12`, `frontend/src/pages/delivery.tsx`.

### F2 — Etkin davranış tek bir ayar önceliğine indirgenemez

Operasyonel politika DB override -> env -> default şeklinde çözülüyor. ClamAV
instance ayarı, env ve eski ayar fallback'leri kullanıyor; clamd kendi sınırlarını
ayrıca uyguluyor. Storage custom politikası environment grant'lerini birleştirmiyor,
yerine geçiyor. ICAP config başlangıçta yükleniyor. Profil kuralları ise sıralı,
ilk eşleşme esaslı ve kabul anında donduruluyor.

Dolayısıyla tek bir evrensel 'öncelik sırası' göstermek yanlış olur. Her alan için
kaynak ve miras zinciri; her iş akışı için uygulama sırası ayrı açıklanmalı.

Mevcut olumlu parçalar var: Limits ekranı etkin değeri/kaynağını gösteriyor;
profil `OutsideRules` bölümü API/ICAP sınırlarını özetliyor. Bunlar korunmalı,
genişletilmeli; yokmuş gibi yeniden yapılmamalı.

Kanıt: `app/services/scan_policy.py:115`, `app/engines/clamav.py:89`,
`app/engines/clamav.py:959`, `app/services/client_storage_policy.py`,
`app/icap/config.py`, `frontend/src/pages/client-profiles.tsx:28`.

### F3 — Boyut ve süre ayarları birbirine yakın görünse de farklı şeyleri sınırlar

Boyut açısından HTTP istek gövdesi, dosya politikası, ICAP gövdesi, deferred dosyası,
arşiv açılımı, adapter dosya sınırı ve clamd iç sınırları aynı şey değildir.
Özellikle multipart gövde sınırı dosyanın byte sınırına eşitmiş gibi sunulmamalı.
Bir dosyayı kabul etmek, her motorun onu tam tarayabileceğini ispatlamaz.

Süreler de farklıdır: API'nin ilk yanıtı beklemesi, ICAP'in nihai kararı beklemesi,
motor timeout'u, queue beklemesi ve job lease'i tek bir timeout değildir.
Örneğin API'nin kabul yanıtı vermesi taramanın iptal edildiği anlamına gelmez.

Somut örnek: 200 MiB üzerinde hafif kontrol kuralı varken ICAP tavanı 50 MiB ise
250 MiB dosya kurala ulaşmaz. Gateway fail-closed ise bloklanır; fail-open ise
taranmadan geçebilir. Bu, profil ile gateway ayarlarının tek bir değerle çözülmesi
gerektiği anlamına gelmez; fark açıkça gösterilmelidir.

Kanıt: `app/services/upload_admission.py`, `app/icap/config.py`,
`app/services/archive_extractor.py`, `app/engines/clamav.py`.

### F4 — Etkin değerin gözlendiği süreç ve tazeliği eksik

Web API'nin okuduğu environment, ICAP veya uzak Windows worker'ın environment'ı
olmayabilir. Worker'da mount, clamd erişimi veya kaynak farklı olabilir. Web ekranı
bunu bilmeden deployment genelinde etkinmiş gibi konuşmamalı.

Etkin yapılandırma özeti 'bu API sürecinin değeri', 'gateway'in son raporladığı',
'worker'ın son doğruladığı' ayrımını taşımalı. Güncelliğini kaybetmiş rapor gerçek
zamanlı teyit gibi gösterilmemeli. Raporlanmayan bilgi için 'bilinmiyor' korunmalı.

### F5 — Hazırlık kontrolü var, uçtan uca sonuç açıklaması yok

Connection ekranı önemli bir mevcut iyileştirme. Müşteri/profil ve bağlantı yöntemi
hazırlığını, endpoint'leri ve motor uygunluğunu gösteriyor. Ancak backend'in mevcut
readiness okuması varsayılan profile odaklı; bütün named profile/kural/dosya
senaryolarının simülasyonu değil. Sağlıklı motoru veya ağ erişimini de ispatlamıyor.

Eksik olan bir müşteri ve gönderim yolu seçilince etkin zincirin açıklanması:
ulaşılabilen kural, seçilen motorlar, worker uygunluğu, taşıma sınırları ve sonucu
belirsiz bırakabilecek koşullar. Bu, 'her şey hazır' isimli tek yeşil lambaya
indirgenmemeli.

Kanıt: `frontend/src/pages/client-setup.tsx`, `app/services/client_readiness.py:87`.

### F6 — Güvenlik politikası kavramları aynı isim altında toplanmamalı

Hash allowlist bir bilgi bulgusudur; başka motorun tespitini bastırmaz. İstisna ise
belirli dosyanın kararını değiştirir ve gerekçe/kapsam/süre taşır. Allow without
scanning başka; Light check başka; motorların tamamının başarıyla taraması başka.
Bunların hepsini sadece 'izin ver' anahtarı altında toplamak sadeleştirme olmaz.

Yeni ekranlar kararı, tarama kapsamını ve kayıtlı riski ayrı göstermeli. İstisnanın
etkisi, yeni kabul edilen taramalarla sınırlı routing değişiklikleri ve daha önce
kaydedilmiş snapshot'ların korunması anlaşılır biçimde belirtilmeli.

### F7 — Klasör taraması profil ekranının verdiği beklentiyi her zaman karşılamıyor

Klasör formunda doğru uyarı mevcut: Scan kuralına eşleşen dosya tam tarama hazır
olmadığından bekliyor. Ancak profili düzenlerken aynı kuralı kullanan izlenen
klasörlerin bu sınırlaması görünmüyor. Yönetici 'profil tarıyor' ile 'folder tarıyor'
arasında hatalı eşitlik kurabilir.

Profil kullanım özeti, bu profile bağlı folder'ları ve bekleyen full-tier yeteneğini
göstermeli. Sadece uyarı yazmak yerine gözlemlenen full_pending sayısına gitmeli;
bu sayı bounded/cached bir operasyonel okuma olmalı.

Kanıt: `frontend/src/pages/storage-location-form.tsx`,
`docs/architecture/STORAGE_PROTECTION.md`.

### F8 — Somut doğruluk ve metin sorunları

1. Profil kural editörü `1024 * 1024` hesabını MB diye etiketliyor. Limits formu MiB
   diyor. Aynı byte standardı ve tutarlı etiket kullanılmalı; var olan kayıtların
   anlamı değiştirilmemeli.
2. `deployment_http_ceiling_bytes()` hatalı sayısal env değerinde görünüm için
   varsayılana dönebiliyor; gerçek admission aynı hatada 503 veriyor. Dolayısıyla
   admin geçerli bir tavan görürken yüklemeler çalışmayabilir. Okuma, 'geçersiz /
   uygulanamıyor' durumunu açık taşımalı. Bu bir kod yolu tespiti; canlı kurulumda
   böyle bir değer olduğunu iddia etmiyor.
3. 'Test connection' düğmesi gerçekte worker check isteği kuyruğa alıyor. Mevcut
   işlem mesajı doğru olsa da düğme adı anlık bağlantı testi beklentisi yaratıyor.
   'Run health check' / 'Sağlık kontrolü iste' gibi bir ad daha doğru.
4. Kuralların çekirdek davranışı ile eski/managed uyumluluk ayarları aynı düzeyde
   görünmemeli. `MASP_ICAP_BLOCK_ARCHIVES` ve `BLOCK_ON_REVIEW`, v2 rule profile'ın
   kararını belirlemiyor; eski kayıt/uyumluluk bağlamı belirtilmeli. Transport
   tavanı ve cevapsızlık davranışı bundan ayrıdır.
5. `MASP_ARCHIVE_MAX_*` kodda okunuyor; pilot/prod compose bu değişkenleri aktarmıyor.
   Env dosyasına bir satır eklemenin çalışan servisi etkileyeceği varsayımı burada
   geçerli değil. Desteklenen alanlar açıkça forward edilmeli ve belgelenmeli.

Kanıt: `frontend/src/components/profile-rules.tsx:13`,
`frontend/src/pages/scan-policy.tsx`, `app/services/upload_admission.py:23`,
`frontend/src/pages/engines.tsx:152`, `app/services/profile_rules.py`,
`docs/architecture/PROFILE_RULES.md`, `app/services/archive_extractor.py`,
`docker-compose.pilot.yml`, `docker-compose.prod.yml`.

## Önerilen yönetici deneyimi

### 1. Ortak yapılandırma merkezi; tek dev editör değil

'Yapılandırma' girişi görev kartları ve mevcut editörlere doğrudan bağlantılar sunsun:

- Entegrasyon bağlamak -> müşteri, bağlantı, profil, kimlik bilgileri.
- Dosya davranışını değiştirmek -> müşteri profilleri, kurallar, hash listesi, istisnalar.
- Tarama kapasitesini düzenlemek -> motorlar, worker'lar, pool'lar.
- Depolama bağlamak -> backend görünümü, müşteri yetkileri, izlenen klasörler.
- Bildirim/saklama yönetmek -> olay seçimi, teslimat durumu, retention politikası ve işlem.
- Sunucu ayarlarını incelemek -> salt okunur deployment envanteri.

Mevcut operasyon ekranları korunmalı. 'Queue durumunu gör' ile 'worker kapasitesini
ayarla' ayrı görevlerdir; aynı nesneye ait olmaları tek sekmede olmalarını gerektirmez.
İlk aşamada route taşıma yerine merkezi dizin ve çapraz bağlantılar yeterli.

### 2. Her ayara ortak açıklama sözleşmesi

Her kayıt şunları belirtmeli:

- Anlamı, birimi, kapsamı ve hangi kaynaktan çözüldüğü.
- Geçerli, geçersiz, bilinmiyor veya güncel değil durumu.
- Nerede değiştirileceği; UI'dan düzenlenebilir olup olmadığı.
- Yeni kabul edilen dosyalara mı, mevcut queued işlere mi, sonraki teslimat döngüsüne
  mi etki ettiği; yeniden başlatma gerekip gerekmediği.
- Hangi süreç/node üzerinde gözlendiği ve ne zaman raporlandığı.
- Bağımlı ayarlar ve kontrol edilemeyen dış sınırlamalar (proxy/firewall gibi).

Örnek: 'ICAP dosya tavanı: 50 MiB; gateway X'in 12 sn önce raporladığı değer;
startup config; ilgili gateway yeniden başlatılınca uygulanır; profilden önce çalışır.'
Worker'a ait config için API'nin değeri yerine worker raporu veya 'bilinmiyor' gösterilmeli.
Secret değerleri, hash/prefix'leri ve filesystem root'ları bu envantere konmamalı.

### 3. Etkin davranış görünümü

Müşteri + profil + yol (API, ICAP, deferred, folder) seçimiyle sınırlı bir özet:

| Katman | Soru |
|---|---|
| Kabul | Bu dosya hangi transport sınırına ulaşır? Kurala ulaşabilir mi? |
| Profil | İlk hangi kural eşleşir; hangi motorlar seçilir? |
| Yürütme | Motor etkin mi, bu source için uygun mu, hangi pool/node çalıştırabilir? |
| Kapasite | Boyut, arşiv açılımı veya motor yeteneği nedeniyle atlanabilir mi? |
| Karar | Eksik sonuç olursa ne olur; ilgili hash istisnası var mı? |
| Sonrası | Olay üretimi ve teslimat zinciri nasıl; saklama hangi politikaya bağlı? |

Bu tablo gerçek malware sonucu veya erişilebilirlik ispatı değildir. Profil öncesi
kabul, engine eligibility ve recorded snapshot ayrımları ortak backend yardımcılarıyla
sunulmalı; React yeni bir karar motoru yazmamalı.

### 4. Yan etkisiz kural denemesi

Boyut, beyan edilen uzantı ve ayrı belirtilen içerik ailesi girilsin. Çıktı,
eşleşen kural, seçilen motorlar, transport engeli ve açıklama olsun. Bu bir tarama
veya güvenli/zararlı hükmü değil; metadata ile sınırlı politika önizlemesidir.
Uzantıdan içerik ailesi uydurulmamalı; masquerade/header eşleşmesinde bilgi eksikse
'bu veriyle belirlenemiyor' denmeli. Hiçbir provider çağrılmamalı, quota harcanmamalı,
örnek yüklenmemeli veya scan/history kaydı açılmamalı.

Kural çakışması analizi ilk sürümde kanıtlanabilir gölgelenmelerle sınırlı olsun.
Sadece kısmi koşul benzerliğinden 'bu kural hiç çalışmaz' sonucu çıkarılmamalı.
Önizleme yanıtı current revision/fingerprint taşımalı; kaydetme anında tekrar
validasyon yapılmalı. Önizleme sonraki bir kabulün garantisi değildir.

### 5. Bağımlılık ve değişiklik etkisi

Motor, profil veya pool'da 'nerede kullanılıyor?' bağlantısı gösterilsin. Disabled
pool veya eksik worker yüzünden seçili motorun çalışamayacağı profil bağlamında
açıklansın. Varsayılan profil değişiminde etkilenen ICAP binding'leri, profil
kuralı değişiminde ilgili folder'lar listelensin. İlişkiler keyset/bounded sorgularla
okunmalı; her sayfada bütün graph veya engine çıktısı yüklenmemeli.

### 6. Daha anlaşılır kaydetme

Genel 'Confirm' yerine değişen alanların eski/yeni değeri ve etkisi gösterilsin.
Özellikle istisna, müşteri kapatma, varsayılan profil ve pool bağlama işlemleri için.
Kapsam tek ekrana indirgenirken mevcut CSRF, admin kontrolü, revision/fence ve
kilitler korunmalı. Birden fazla bağımsız mutation'ı tek düğmeye bağlayıp atomiklik
varmış gibi gösterilmemeli. Başarılı kayıttan sonra tek taze okuma; belirsiz yazma
sonucunda açık yenileme ve hiçbir otomatik replay olmaması devam etmeli.

Salt okunur deployment kataloğu host güvenliği için read-only kalmalı. Web süreci
Docker restart, dosya root'u veya tüm env/secrets editörüne dönüştürülmemeli.

## Aşamalı uygulama önerisi

| Aşama | Çıktı | Öncelik / bağımlılık |
|---|---|---|
| A | MiB etiketleri, geçersiz HTTP tavanı görünümü, health check adı, archive env forwarding | P1: kısa, somut doğruluk düzeltmeleri; her biri kendi runtime riskine göre doğrulanmalı |
| B | Görev odaklı yapılandırma merkezi; kapsam/kaynak/uygulama zamanı sözleşmesi | P1: mevcut davranışı taşımadan anlaşılabilirlik |
| C | Müşteri/profil/yol bazlı etkin davranış özeti; mevcut readiness ve OutsideRules üzerine | P1: backend okuma kontratı ve sınırlı süreç raporları gerekir |
| D | Yan etkisiz kural önizlemesi ve kanıtlanabilir uyarılar | P2: ortak rule resolver ve revizyon doğrulaması |
| E | Nerede kullanılıyor, değişiklik etkisi ve hedefli config geçmişi | P2: mevcut audit'in üstüne secret içermeyen alan bazlı kayıt tasarımı |
| F | Doğrulanmış profil şablonları ve entegrasyon kurulum rehberi | P3: C/D sonrası; gizli varsayımlar ve sessiz varsayılanlar olmadan |

Şablonlar 'her yerde en iyi/güvenli' diye sunulmamalı. Mevcut motor ve transport
sınırlarına göre doğrulanmalı, kaydetmeden önce bütün seçimler açıkça gösterilmeli.
İlk sürüm için toplu config import/export, genel JSON editörü, otomatik restart veya
her servisin tüm ayarını UI'dan düzenlemek gerekli değil.

## Başarı nasıl ölçülür?

- Yeni admin, belirlenmiş bir müşteri ve yol için dosya sınırını ve kaynak katmanını
  hosta bağlanmadan bulabiliyor; raporlanmayan bilgiyi de ayırt edebiliyor mu?
- 250 MiB ICAP örneğinde neden profil kuralına ulaşılamadığını ve düzeltme yerini
  bulabiliyor mu? API ile ICAP'i karıştırmadan açıklayabiliyor mu?
- 'Bu profil hangi motor/node ile çalışır, yapılandırma mı sağlık mı?' ayrımı açık mı?
- Bir folder'ın Scan kuralında neden full_pending kaldığı profil bağlamında görülebiliyor mu?
- Bir değişikliğin mevcut taramayı mı yeni kabulleri mi etkileyeceği kaydetmeden anlaşılıyor mu?
- İzlenecek metrikler: görev tamamlama süresi, yanlış ekran ziyaretleri, yanlış ayar
  katmanı seçimi ve yardım ihtiyacı. Eşikler ilk kullanıcı denemesiyle belirlenmeli;
  şu anda ölçülmüş iyileşme veya skor iddiası yok.

Teknik kabul: secret/root sızıntısı olmaması, bounded read ve tutarlı snapshot,
source ayrımı, explicit fail/unknown durumları, CSRF/revision kontrolleri ve eski
routing snapshot davranışının korunması; ayrıca gerçek admin görevleriyle kısa
kullanılabilirlik çalışması. Menü değişimi tek başına başarı sayılmamalı.
