# Yönetim ekranlarının görev ve yerleşim incelemesi

Tarih: 2026-11-13. Durum: kullanıcı onayıyla temel görev mimarisi uygulandı;
bağlantı yöntemine göre yeni sistem kurulumu ve müşteri detayının tamamen
sadeleştirilmesi açık. Aşağıdaki bulgular değişiklik öncesinin incelemesidir.

## Uygulanan düzeltmeler

- Tek `frontend/src/lib/navigation.ts` kaydı ana menüyü, alan gezinmesini ve
  konum bilgisini belirliyor. Altı alan: Scans, Integrations, Storage, Policies,
  Scan infrastructure, Administration. Eski on sekmeli System yapısı kaldırıldı.
- Storage her zaman bulunabilir. Watched folders, Sources & access, File intake
  ve Folder findings aynı alanda. Klasör ekleme doğrudan buradan başlar.
  Analist yalnız mevcut sonuç yetkilerini görür; kaynak ve alım yönetimi admin'dir.
- Sources & access ve Scan profiles sınırlı/sayfalı bağlı sistem seçimiyle açılır.
  Seçili sistemin adı ve anahtarı görünür; mevcut editörler yeniden kullanılır.
  Müşteri dialogundaki kısa yollar korunur; bağımsız editörün URL'si paylaşılabilir.
  Profil sahipliği, depolama yetkileri ve revizyon korumaları değişmez.
- ICAP gateways Entegrasyonlar'da; olay seçimi ve SIEM teslimatı Yönetim /
  Notifications'ta. İki ekran aynı güvenli durum okumasının ilgili kısmını gösterir.
  Yeni dar kapsamlı kayıt uçları bildirim değişikliğinin limitleri, limit
  değişikliğinin de bildirim ayarını yeniden yazmasını önler.
- Manual scans ve Integration scans isimleri mevcut kaynak sınırlarını açıklar.
  Hash list ve File exceptions Politikalar'dadır. Saklama politikası ve temizlik
  aynı ekrandadır; altyapı özetindeki ikinci politika kartı kaldırılmıştır.
- Connection içindeki tekrarlanan motor tablosu kaldırıldı; ayrıntı için Overview'a
  bağlanır. Overview hâlâ kısa bağlantı durumunu gösterir; tüm müşteri sekmeleri
  birleştirilmiş değildir.
- Eski profil/depolama adresleri yeni esas adreslere query/fragment korunarak gider.
  `/system/intake` File intake'a yönlenir. Eski `/system/delivery` iki yeni hedefi
  gösterir. Sağlık uyarıları doğrudan doğru görev alanına bağlanır.
- Configuration ana menü değildir; açıklayıcı rehber olarak erişilebilir.
  Klavye için içeriğe geçiş bağlantısı, mobil menüde Escape/fokus davranışı ve
  roller arasında tutarlı görev sırası korunur. Gezinti yazdırılan rapora eklenmez.

## Referans çerçevesi ve kanıt sınırı

Bu değerlendirme bir sertifikasyon veya başka ürünlerle tam özellik eşitliği
iddiası değildir. Kullanılan resmî örüntüler:

- [IBM Carbon UI shell](https://carbondesignsystem.com/components/UI-shell-left-panel/usage/):
  ana ve ikincil gezinmeyi ayırmak; gezinme ağacına üçüncü bir seviye eklemek yerine
  yerel bölüm gezinmesi kullanmak. MASP'ye uygulanışı altı alan ve alan sekmeleridir.
- [WCAG 2.2 tutarlı gezinme açıklaması](https://www.w3.org/WAI/WCAG22/Understanding/consistent-navigation.html):
  tekrar eden gezinmenin göreli sırasını korumak. Paylaşılan görev kaydı bu amacı
  destekler; tam WCAG denetimi yapılmadı.
- [Microsoft Defender portal](https://learn.microsoft.com/en-us/defender-xdr/microsoft-365-defender-portal):
  ilişkili güvenlik çalışmalarını ortak bir portalda toplama örneği. Buradan yapılan
  tasarım çıkarımı, ilgili görevleri birlikte bulundurmak; farklı kuyruk ve sonuç
  anlamlarını tek bir başarılı/başarısız durumuna indirgemek değildir.

Doğrulama: 250 frontend testi; browser API'de 187 test (4 koşullu atlama),
sağlık/ayar/audit seçiminde 62 test (9 koşullu atlama); toplam 236 backend testi
geçti. 13 farklı Edge görev senaryosu geçti (iki çalıştırmada ortak klasör senaryosu
tekrarlandı). Üretim build'i, sözleşme eşitliği ve diff biçim kontrolü geçti.
Bildirim kaydının limitlere dokunmaması, yetkiler, eski bağlantılar, müşteri bağlamı,
onay sırasında sistem seçimi, mobil menü ve iki tema kontrol edildi.
PostgreSQL ortamına bağlı kontroller bu oturumda çalışmadı. Canlı kullanıcı görev
deneyi, erişilebilirlik denetimi, yük testi ve dağıtım yapılmadı.

## Öncelikli kalan işler

1. **Yönteme göre kurulum:** yalnız ICAP/depolama kullanan sistemde API credential
   zorunluluğunu kaldırmak. İsteğe bağlı credential, atomik client/profile/routing
   oluşturma ve secret yaşam döngüsüyle birlikte ayrı doğrulanmalı.
2. **Müşteri ayrıntısı:** Connection ile API access'i birleştirmek; isim/etkinlik
   alanını Genel bölüme almak. Form onayları, secret temizliği, dialog kilitleri ve
   belirsiz yazma sonrası açık yenileme davranışı korunmalı.
3. **Bildirim görünürlüğü:** klasör bulgularının ayrı outbox'ı mevcut SIEM durum
   sayılarına dahil değildir. Şimdi ekranda bu sınır açık; ileride ayrı sınırlı
   okuma ve kaynak bazlı teslimat görünümü gerekir.
4. **Kullanılabilirlik kabulü:** aşağıdaki görevleri menü adı söylemeden bir yöneticiye
   yaptırıp süreyi, yanlış bölüm ziyaretini ve yardım ihtiyacını ölçmek. Daha kolay
   kullanılacağı beklentisi ölçülmüş iyileşme olarak raporlanmamalı.

## Sonuç ve önceki yaklaşımın düzeltmesi

Sorun ayarların açıklamasından önce bilgi mimarisinde. Ana menü, sekmeler ve sayfa
başlıkları bazen teknik modülü, bazen veri kaynağını, bazen kullanıcının görevini
temsil ediyor. Bir görevin hangi alana ait olduğunu öğrenmek için uygulamanın iç
yapısını bilmek gerekiyor.

Önceki Configuration merkezi mevcut yerleşimin üstüne bir bağlantı katmanı ekledi.
Kaynak açıklamaları, kural önizlemesi ve Used by faydalı; fakat ekranların asıl
sahipliğini değiştirmedi. Bu yüzden merkezi eklemek dağınıklığı çözmüş sayılmaz.
Öncelik yeni özellikler eklemekten, mevcut görevlerin esas yerini düzenlemeye kaymalı.

Kanıt kapsamı: route ağacı, ana menü, System/client/storage sekmeleri, ekranların
okuduğu ve yazdığı bilgiler, müşteri oluşturma sözleşmesi ve mimari sınırlar.
Canlı kullanıcı gözlemi, tıklama ölçümü veya kullanılabilirlik deneyi yapılmadı.
Aşağıdaki sorunlar kodda gözlenen yerleşim; önerilerin daha kolay bulunacağı bir
tasarım hipotezidir ve görev denemeleriyle doğrulanmalıdır.

## Bulgular

| Öncelik | Gözlenen durum | Yönetici açısından sorun | Öneri |
|---|---|---|---|
| P1 | `SYSTEM_TABS` 10 sekme: overview, nodes, pools, queue, retention, intake, ICAP/SIEM, engines, hash list, exceptions | System sınırı öngörülemiyor; politika, altyapı ve dosya operasyonu karışıyor | System'i tarama altyapısı ile sınırla; diğer görevleri kendi alanlarına taşı |
| P1 | Folder scanning ana menüde; deferred intake System'de; izinler ve klasör tanımı müşteri Storage sekmesinde | Depo bağlama, klasör ekleme ve başarısız dosyayı bulma üç farklı yerde | Tek Depolama alanı; müşteri bağlamı filtre olarak korunsun |
| P1 | `delivery.tsx` ICAP ve SIEM'i aynı sayfada; SIEM olay seçimi `scan-policy.tsx` içinde | Gelen dosya akışı ile dışarı gönderilen olaylar aynı görev gibi sunuluyor | ICAP Entegrasyonlar altında; olay seçimi ve teslimat Bildirimler altında |
| P1 | Dashboard yalnızca manual/non-child; API ledger API ve ICAP'i kapsıyor | Dashboard genel ürün özeti sanılabilir; ICAP geçmişi API adının arkasında | Taramalar alanında açık Manuel / Entegrasyon kaynak görünümleri; genel toplam icat etme |
| P1 | `ClientCreateBody` API credential gövdesinden türiyor; oluşturma ekranı API token istiyor | Yalnız ICAP veya depolama kullanan sistem de API kimliği oluşturmak zorunda | Bağlantı yöntemi seçimine göre kurulum; API erişimi gerektiğinde credential ekle |
| P2 | Client Overview ve Connection ikisi de readiness, motor/routing bilgisi gösteriyor | Benzer ama farklı zamanda/bağlamda okunan iki özet arasında seçim gerekiyor | Overview kısa durum/eksik adım; Connection endpoint, yöntem ve API erişiminin tek esas yeri |
| P2 | Müşteride Settings yalnız isim/etkinlik; Credentials ayrı tam sekme; uzun profil yönetimi dialog içinde | Genel başlıklar dar iş yapıyor; kurulum tek URL ile paylaşılmıyor | İsim/etkinlik Genel bölümünde; credentials Bağlantı ve erişim içinde; uzun iş için adreslenebilir detay sayfası |
| P2 | Hash list ve exceptions System/Engines içinde | Kurumsal dosya politikası bir motorun teknik ayarı sanılabiliyor | Politikalar alanı; hash list ve istisna anlamları açıkça ayrı kalsın |
| P2 | Retention policy System overview'da; cleanup ayrı; kalıcı değer deployment'ta | Süreyi incelemek ile temizliği çalıştırmak farklı yerlerden aranıyor | Saklama ve temizlik aynı çalışma alanında; deployment değeri salt okunur |
| P2 | Runtime queue henüz scan kaydı oluşmamış deferred işleri içermez | Dosya bekliyor fakat tarama kuyruğunda yok; iş kaybolmuş sanılabilir | Aynı yaşam döngüsü dili: dosya alımı → tarama kuyruğu → sonuç; ayrı kuyruklara bağlamlı geçiş |
| P2 | Folder scanning menüsü ancak worker/folder görünce açılıyor | Yönetici kurmadan önce özelliğin nereden kurulacağını bulamayabilir | Admin için Depolama kalıcı; boş durumda kurulum girişi. Analistin yalnız yetkili sonuçları görmesi korunsun |
| P2 | Configuration aynı hedefleri tekrar listeliyor; breadcrumb route prefix'lerinden ayrı üretiliyor | Menü, merkez ve breadcrumb birbirinden kopabilir | Geçiş sonrasında merkez ana menüden kalksın veya yardım/ilk kurulum olsun; gezinme tanımı ortak olsun |

Kanıt dosyaları:

- `frontend/src/components/workspace-navigation.tsx`, `section-tabs.tsx`.
- `frontend/src/main.tsx`: kaynak kapsamları, route yerleşimi, ayrı breadcrumb tablosu.
- `frontend/src/pages/storage.tsx`, `client-storage.tsx`, `intake.tsx`, `runtime.tsx`.
- `frontend/src/pages/delivery.tsx`, `scan-policy.tsx`, `system-overview.tsx`, `retention.tsx`.
- `frontend/src/pages/client-overview.tsx`, `client-setup.tsx`, `service-clients.tsx`, `client-credentials.tsx`.
- `app/services/credential_admin.py`: `ClientCreateBody(CredentialBody)` ve atomik bundle oluşturma.

## Kullanıcının önerisine de sınır koymak

### Depolamayı birleştirmek doğru; işlemleri tek listeye düzleştirmek yanlış

Üç parça aynı kaynak ve izin bağlamını paylaşır; tek üst alan mantıklı. Ancak
deferred intake bildirilen nesneyi alıp tarama kabulüne götürür, folder scanning
dosyayı kendisi keşfeder ve ayrı envanter/bulgu tutar. Mevcut klasör fazında Scan
kuralının dosyası `full_pending` kalır. Bunları tek durum sütununda “tarandı” diye
sunmak gerçek davranışı örter. Aynı bölümde ayrı, adlandırılmış iş akışları olmalı.

Depolama da iki anlama gelebilir: dış dosya kaynakları ve MASP'nin tuttuğu örnekler.
Bu bölüm **dış dosya kaynakları** içindir. MASP'nin sonuç/örnek saklama süresi ve
temizliği Yönetim altında kalır; depodan dosya silme veya karantina anlamı taşımaz.

### Her müşteri ayarını merkezden düzenletmek de gereksiz dolaşma yaratır

Müşteriden depolama iznine, profilinden motora ve sonuçtan istisnaya kısa yol gerekir.
Ama kısa yol ikinci bir form sahibi yaratmamalı: aynı editörü, aynı revizyon ve
işlem sonucuyla, ilgili müşteri/profil seçili açmalı. Önceki “müşteri Storage'ı
sadece link olsun” önerisi fazla katıydı; aynı editör bağlam içinde de açılabilir.

### En az menü her zaman en anlaşılır menü değildir

Tek dev Settings veya System ekranı, mevcut dağınıklığı bir sekme şeridine taşır.
Hedef altı sayısına ulaşmak değil, görevlerin tahmin edilebilir bir esas yeri olması.
Sık kullanılan dosya gönderme ve arama eylemleri erişilebilir kalmalı.

### Ayrı teknik veritabanı/API, ayrı kullanıcı menüsü gerektirmez

Manuel ve otomasyon geçmişi aynı gezinme alanında farklı kaynak görünümleri olabilir.
Kaynak kapsamları, admin/analyst yetkileri ve farklı sonuç anlamları korunur.
Benzer şekilde bir sayfayı bölmek aynı anda bütün backend servislerini bölmeyi gerektirmez.

## Önerilen hedef yerleşim

Bu yerleşimin ana alanları uygulanmıştır; yöntem bazlı kurulum ve müşteri ayrıntısının
birleştirilmesi yukarıdaki açık işlerde izlenir.

| Ana alan | İçeriği | Sınırı |
|---|---|---|
| Taramalar | Manuel taramalar, entegrasyon taramaları, dosya gönderme, hash sorgulama; rapor/arsiv/batch bu akışların detayları | Klasör hafif kontrol bulguları tam tarama geçmişine karışmaz; hash sorgusu tarama kaydı üretmez |
| Entegrasyonlar | Bağlı sistemler, yöntemlere göre bağlantı/erişim, ICAP gateway durumu | Service client kimliği korunur; API/ICAP/depolama kullanımı tek kimliğe bağlı olabilir |
| Depolama | Kaynaklar ve erişim, izlenen klasörler, dosya alımı, klasör bulguları | Sadece dış kaynaklar; admin yönetimi ve analyst sonuç yetkileri ayrı |
| Politikalar | Müşteri seçili tarama profilleri, hash listesi, dosya istisnaları | Profil sahipliği müşteride kalır; yeni global/paylaşılan profil semantiği oluşmaz |
| Tarama altyapısı | Sağlık, motorlar, worker'lar, worker grupları, tarama kuyruğu | Policy, retention, intake ve SIEM burada tam editör olarak tekrarlanmaz |
| Yönetim | Operatörler, limitler/API yanıt ayarları, bildirimler, saklama/temizlik, denetim kaydı | Bildirimler olay seçimi + teslimat görünümünü birleştirir; deployment secrets/roots web editörü olmaz |

Hesabım, tema ve Hakkında yardımcı alanlarda kalır. Analyst menüsü yalnız yetkili
görevleri sunar; yeni gruplama hiçbir endpoint yetkisini genişletmez.

Politikalar / profiller için ilk uygulama müşteri seçimini koruyabilir. Tüm
müşterilerin profillerini gösteren katalog istenirse bu ayrı bir bounded okuma
geliştirmesidir; tarayıcıdan bütün müşterileri ve profilleri indirmek çözüm değildir.
Müşterinin profil bağlantısı aynı düzenleyiciyi o müşteriyle açar.

Müşteri detayının olası düzeni: kısa Genel bakış, Bağlantı ve erişim, Tarama profilleri,
Depolama. İsim ve etkinlik Genel bakış içindeki açık Genel ayarlar bölümünde olur.
Connection içine alınan credential işlemleri kendi onayını, secret temizliğini ve
yazma sonucunu korur; tek bir “hepsini kaydet” düğmesi oluşturulmaz. Mevcut dialog
hızlı işler için kalabilir; uzun işlerin adreslenebilir sayfası birinci sınıf olmalı.

## İsimler

Arayüz İngilizce kalacaksa öneriler: Scans, Integrations, Storage, Policies,
Scan infrastructure, Administration. Ürün dili değişikliği bu önerinin kapsamında değil.

- Service clients → Connected systems; açıklamada teknik service-client kimliği.
- API ledger → Integration scans; API ve ICAP kaynakları açık.
- Dashboard → Manual scans (mevcut kapsam için). Gerçek genel bakış ayrı veri işidir.
- Deferred intake → File intake; manifest/ref yöntemleri alt açıklamada.
- Worker pools → Worker groups; teknik pool anahtarı ayrıntıda kalabilir.
- Credentials → API access; bağlantı yönteminin içinde.
- Retention → Retention & cleanup; kalıcı süre ile açık silme işlemi ayrı kontroller.
- Hash allowlist ve dosya istisnası aynı “Allow” adı altında birleşmez.

## Uygulama sırası ve kapsam

1. Ekranların esas yerini ve adlarını sabitle; route → ana alan → alt bölüm →
   rol → bağlam eşlemesini ortak gezinme tanımına taşı. Mevcut URL'ler çalışsın.
2. Depolamayı uçtan uca düzenle: merkezi kurulum/izin/klasör/alım/sonuç geçişleri;
   müşteri seçimi korunarak aynı editörler kullanılsın. Yeni özelliği admin'den gizleme.
3. ICAP ile SIEM'i ayır; bildirim olay seçimini teslimatın yanına taşı; retention
   politika/temizliğini aynı alanda göster; kalan System'i altyapı ile sınırla.
4. Müşteri Overview/Connection tekrarını kaldır; yönteme göre kurulum ve isteğe
   bağlı API credential oluşturmayı kendi backend/CSRF/atomiklik testleriyle ele al.
5. Taramalar kaynak sekmeleri ve Politikalar bağlamını düzenle. Yeni profil kataloğu
   gerekiyorsa bütçeli/sayfalı okuma tasarla. Configuration merkezi ana menüden çıkar.
6. Rol, deep link, geri dönüş, mobil, yazma sırasında gezinme, belirsiz yazma sonrası
   açık yenileme ve kaynak kapsamı regresyonlarını doğrula; sonra yayın hazırlığı.

Saf ad/yerleşim değişiklikleri ile yeni okuma, isteğe bağlı credential ve form
yerleştirme değişiklikleri aynı riskte değil. Backend sınırlarını sırf menüleri
birleştirmek için gevşetme. Mevcut kaynak açıklamaları, önizleme ve Used by yeni
yerlerine taşınabilir; yararlı işi silmeye gerek yok.

## Görevlerle kabul

Kullanıcıya menü öğesinin adı verilmeden başlangıç noktası, yanlış alan ziyaretleri,
geri dönüşler ve dış yardım ihtiyacı gözlensin. Ölçülmüş iyileşme iddiası yok.

| Görev | Beklenen esas yol / sonuç |
|---|---|
| Bir depoyu müşteriye aç ve klasör izlemeye başla | Depolama; müşteri, izin ve profil bağlamı kaybolmaz |
| “Gönderilen dosya neden taramalarda yok?” | Dosya alımı → varsa tarama kaydı; alınmamış dosya boş geçmiş olarak sunulmaz |
| “ICAP dosyayı neden geçirdi?” | Entegrasyonun gateway bilgisi + profil; fail-open ve tarama sonucu ayrılır |
| “SIEM'e neden olay ulaşmadı?” | Bildirimler; olay seçimi, kuyruk, teslimat durumu aynı görev alanında |
| Yalnız ICAP kullanan yeni sistem kur | İstenmeyen API credential zorunlu değil; bu değişiklik henüz uygulanmadı |
| Bir motoru başka worker grubuna taşı | Tarama altyapısı; bağlı profiller ve sağlık durumu korunur |
| Kuralın hangi dosyayı etkileyeceğini dene | Müşteri/profil bağlamı ve mevcut önizleme; boş/eksik bilgi garantiye dönüşmez |
| Bir dosyaya istisna ver | Politikalar veya rapordan bağlamlı aynı editör; hash allowlist ile karıştırılmaz |
| Saklama süresini öğren ve süresi dolmuş kayıtları temizle | Yönetim / Saklama; süre sahipliği ve silme korumaları açık |
| Analyst olarak klasör bulgusu incele | Yetkili sonuç görünür; kaynak/grant/credential düzenlemesi erişilemez |

Kabulte somut görev akışı üzerinden değerlendirme yapılmalı. Tamamlanan yerleşim ile
açık kalan kurulum, teslimat görünürlüğü ve kullanılabilirlik işleri yukarıda ayrı
izlenir; tüm ürünün kurumsal kabulünün tamamlandığı anlamına gelmez.
