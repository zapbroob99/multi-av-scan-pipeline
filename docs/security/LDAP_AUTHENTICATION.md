# LDAP and Active Directory authentication

MASP supports optional LDAP/Active Directory login alongside its local
accounts. It uses the normal MASP login form and session cookie; there is no
separate LDAP-only endpoint.

## Authentication flow

1. If the submitted username belongs to a local MASP account, MASP verifies
   only the local PBKDF2 password. A failed local login never falls through to
   LDAP.
2. Otherwise, the app connects to the directory over LDAPS or StartTLS and
   binds with a read-only service account.
3. It searches for exactly one user using an escaped username filter.
4. It opens a new connection and binds as that user's DN with the submitted
   password. A successful bind proves the password without disclosing or
   storing it in MASP.
5. Direct values from the configured group attribute (normally `memberOf`) map
   the identity to MASP `admin` or `analyst`. A user outside both configured
   groups is denied. Admin wins if both groups are present.
6. MASP creates or refreshes a local shadow record containing only the username,
   directory DN, display name, mapped role, and last login time, then issues the
   existing MASP session cookie.

LDAP shadow users cannot change their password or role in MASP. Their role is
re-synchronized at every successful login. Deleting a shadow user only removes
the local record and sessions; it does not alter the directory, and the record
is recreated on the next authorized login.

## Security properties

- Plain LDAP is deliberately unsupported. Choose `ldaps` or `starttls`.
- Server certificates are required and checked against `MASP_LDAP_HOST`.
  `MASP_LDAP_CA_CERT_FILE` can point to a mounted PEM CA bundle; when unset,
  the container/system trust store is used.
- The bind account should be read-only and restricted to the configured user
  search base and requested attributes.
- LDAP passwords and the bind password are never written to MASP's database or
  audit trail. Keep the bind password in the protected deployment environment
  or the platform's secret manager.
- A case-insensitive collision with an existing local username is denied, so a
  directory identity cannot claim a local or break-glass account.
- Keep at least one tested local admin as a break-glass account. LDAP failure
  does not prevent that account from signing in.
- Version 1 maps direct group values only. Nested/transitive Active Directory
  groups are not expanded by MASP. Configure the MASP groups directly on users
  or use a directory-side attribute/filter that exposes the effective group.

## Configuration

Set these values only on the `app` service; workers and ICAP do not use LDAP.

```dotenv
MASP_LDAP_ENABLED=1
MASP_LDAP_HOST=dc01.corp.example
MASP_LDAP_PORT=636
MASP_LDAP_TLS_MODE=ldaps
MASP_LDAP_CA_CERT_FILE=/run/secrets/corp-ldap-ca.pem
MASP_LDAP_CONNECT_TIMEOUT=5
MASP_LDAP_RECEIVE_TIMEOUT=8

MASP_LDAP_BIND_DN=CN=svc-masp,OU=Service Accounts,DC=corp,DC=example
MASP_LDAP_BIND_PASSWORD=CHANGE_ME_DIRECTORY_SECRET
MASP_LDAP_BASE_DN=OU=Users,DC=corp,DC=example
MASP_LDAP_USER_FILTER=(sAMAccountName={username})
MASP_LDAP_USERNAME_ATTRIBUTE=sAMAccountName
MASP_LDAP_DISPLAY_NAME_ATTRIBUTE=displayName
MASP_LDAP_GROUP_ATTRIBUTE=memberOf
MASP_LDAP_ADMIN_GROUP_DN=CN=MASP Admins,OU=Groups,DC=corp,DC=example
MASP_LDAP_ANALYST_GROUP_DN=CN=MASP Analysts,OU=Groups,DC=corp,DC=example
```

For OpenLDAP, a typical variant is:

```dotenv
MASP_LDAP_BASE_DN=ou=people,dc=example,dc=org
MASP_LDAP_USER_FILTER=(uid={username})
MASP_LDAP_USERNAME_ATTRIBUTE=uid
MASP_LDAP_DISPLAY_NAME_ATTRIBUTE=cn
MASP_LDAP_GROUP_ATTRIBUTE=memberOf
```

At least one of the admin or analyst group DNs must be configured. Group DN
comparison is exact apart from case; copy the canonical DN from the directory.

If a private CA is not already trusted inside the image, mount it read-only and
set the container path, for example in a Compose override:

```yaml
services:
  app:
    volumes:
      - /etc/masp/corp-ldap-ca.pem:/run/secrets/corp-ldap-ca.pem:ro
```

## Rollout and acceptance

1. Keep LDAP disabled and confirm the local admin login works.
2. Allow the app host/container outbound TCP to the directory port.
3. Install or mount the CA, configure the bind account, search base, filter,
   and group DNs, then enable LDAP and restart only the app service.
4. Test one analyst, one admin, a user outside both groups, and a wrong password.
5. Verify **Admin > Users** shows LDAP badges and the expected synchronized
   roles. Verify **Admin > Audit** records successful and denied login outcomes
   without credentials.
6. Remove a test user from both groups, sign out, and confirm a new login is
   denied. Existing MASP sessions are not continuously revalidated against LDAP;
   revoke/delete the shadow account for immediate termination.

No live directory is exercised by the unit suite. Production acceptance must
use the organization's actual certificate chain, directory topology, and group
membership behavior.
