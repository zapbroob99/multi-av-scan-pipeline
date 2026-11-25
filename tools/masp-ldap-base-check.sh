#!/usr/bin/env bash
# Run on the MASP pilot host. Uses the saved search identity for one connection.
set -eu
if [[ $# != 1 || -z "$1" ]]; then
    echo 'Kullanım: sudo bash masp-ldap-base-check.sh KISA_KULLANICI_ADI' >&2
    exit 2
fi
exec masp exec -T app python -u - "$1" <<'PY'
import sys
from urllib.parse import unquote, urlsplit

import ldap3
from ldap3.utils.conv import escape_filter_chars
from app.services import connection_settings, ldap_auth


def show_referrals(result):
    for url in (result.get("referrals") or [])[:5]:
        try:
            parsed = urlsplit(url)
            if parsed.scheme in {"ldap", "ldaps"} and parsed.hostname:
                print("  Yönlendirme hedefi:", repr(parsed.hostname), "DN:", repr(unquote(parsed.path.lstrip("/"))))
        except (TypeError, ValueError):
            continue


def probe(connection, config, username):
    _, result, rows, _ = connection.search("", "(objectClass=*)", ldap3.BASE,
        attributes=["defaultNamingContext", "namingContexts"], time_limit=5)
    naming = {}
    for row in rows or []:
        if row.get("type") == "searchResEntry":
            for key, values in row["raw_attributes"].items():
                naming[key.lower()] = [v.decode("utf-8", "replace") for v in values if v]
    defaults = naming.get("defaultnamingcontext", [])
    contexts = naming.get("namingcontexts", [])
    print("RootDSE kodu:", result.get("result"), "Varsayılan Base DN:", repr(defaults[0]) if defaults else "(bildirilmedi)")
    print("Sunucunun bildirdiği dizin bölümleri:", ", ".join(map(repr, contexts[:20])) or "(bildirilmedi)")
    base = config.base_dn
    candidates = [base]
    alternate = defaults[0] if defaults else contexts[0] if len(contexts) == 1 else None
    if alternate and alternate.casefold() != base.casefold():
        candidates.append(alternate)
    query = config.user_filter.replace("{username}", escape_filter_chars(username))
    for candidate in candidates:
        _, result, rows, _ = connection.search(candidate, query, ldap3.SUBTREE,
            attributes=[config.username_attribute], size_limit=2, time_limit=8)
        code = result.get("result")
        entries = [row for row in rows or [] if row.get("type") == "searchResEntry"]
        print("Aranan Base DN:", repr(candidate), "| LDAP kodu:", code, "| Kullanıcı eşleşmesi:", len(entries))
        show_referrals(result)
        if code == 0 and len(entries) == 1:
            if candidate == base:
                print("SONUÇ: Kayıtlı taban kullanıcıyı buldu. Panelde aynı kısa adla rol ve parola testine geçin.")
            else:
                print("SONUÇ: Kullanıcı bu tabanda bulundu:", repr(candidate))
                print("Bu taban amaçlanan kullanıcı ve grup kapsamıysa panelde User search base alanına kaydedin.")
            return 0
        if code not in {0, 10, 32} or entries:
            print("SONUÇ: Arama tek bir kullanıcıyı doğrulayamadı. Yukarıdaki kodu ve eşleşme sayısını kontrol edin.")
            return 1
    print("SONUÇ: Bu bağlantıda kullanıcı doğrulanamadı. Çalışan uygulamanın etkin host ve Base DN değerlerini karşılaştırın.")
    return 1


def main():
    username = sys.argv[1].strip()
    if not 0 < len(username) <= 255:
        sys.exit("Geçerli bir test kullanıcı adı girin.")
    _, saved = connection_settings.record("ldap")
    env = connection_settings.configuration_environment("ldap", saved)
    env["MASP_LDAP_ENABLED"] = "1"
    config = ldap_auth.load_ldap_config(env, require_role_groups=False)
    print("Kayıtlı hedef:", repr(config.host), config.port, config.tls_mode, "| User search base:", repr(config.base_dn))
    server, auto_bind = ldap_auth._transport(ldap3, config)
    # Query RootDSE directly. Operational names need not exist in the published schema.
    server.get_info = ldap3.NONE
    connection = ldap_auth._bind_search_account(ldap3, config, server, auto_bind)
    try:
        print("Arama hesabıyla bağlantı başarılı.")
        connection.raise_exceptions = False
        return probe(connection, config, username)
    finally:
        connection.unbind()


try:
    sys.exit(main())
except Exception as exc:
    sys.exit("Tanı tamamlanamadı: " + type(exc).__name__)
PY
