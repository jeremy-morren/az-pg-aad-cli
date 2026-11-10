package cli

// Help text taken from Microsoft's documentation, so --help explains each property in
// the same words, with a link for more detail.

// DocsURL is the Microsoft page these explanations come from.
const DocsURL = "https://learn.microsoft.com/en-us/azure/postgresql/security/security-manage-entra-users"

const docsSeeAlso = "\nSee " + DocsURL + " for more detail."

const docPrincipalTypes = `Principal types (--type):
  user     Including tenant local and guest users.
  service  Service principals, including applications and managed identities (connecting
           under their own service credentials).
  group    When a PostgreSQL role is linked to a Microsoft Entra group, any user or service
           principal member of this group can connect with the group role.`

const docObjectID = `Object ID (--oid): the unique object identifier of the Microsoft Entra object.
  - For users, groups and managed identities, find the objectId by searching for the object
    name on the Microsoft Entra ID page in the Azure portal.
  - For applications, use the objectId of the corresponding Service Principal (Azure portal:
    Enterprise Applications), not the app registration's object ID.`

const docAdmin = `--admin: when set, creates a PostgreSQL admin user (member of the azure_pg_admin role
and with CREATEROLE and CREATEDB permissions). Otherwise a regular PostgreSQL user is created.`

const docMFA = `--mfa: enforces multifactor authentication for this PostgreSQL user.
  Important (Microsoft's documentation): "The isMfa flag tests the mfa claim in the
  Microsoft Entra ID token, but it doesn't impact the token acquisition flow. For example,
  if the tenant of the principal isn't configured for multifactor authentication, it
  prevents the use of the feature. And if the tenant requires multifactor authentication
  for all tokens, it makes this flag useless." In short: if MFA is already enforced for the
  whole tenant, --mfa is a no-op.`

const docPrincipalFields = `Fields (from pgaadauth_list_principals):
  name      The name of the role in PostgreSQL.
  type      The type of principal in Microsoft Entra ID: user, group, or service.
  objectId  The identifier of the object in Microsoft Entra ID for this principal.
  tenantId  The identifier of the tenant hosting this principal in Microsoft Entra ID.
  isMfa     true if the role has MFA enforced (see 'azpgaad role create --help' for what
            that does and doesn't mean).
  isAdmin   true if the role is a Microsoft Entra administrator in PostgreSQL.`

const docValidation = `Object IDs are validated by the server itself (pgaadauth's security label provider),
so an invalid one changes nothing and fails with a clear error:
  object ID not found in the tenant   SQLSTATE 0LP01 "Cannot validate Microsoft Entra ID
                                      user … because the OID isn't found in the tenant"
  malformed object ID                 SQLSTATE XX000 "Not a valid OID"
  --type doesn't match the object     SQLSTATE XX000 "Incorrect object type provided for
                                      principal. Given object type: …, actual object type: …"`
