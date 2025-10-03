## Port Details

The app uses HTTPS protocol for communicating with Snowflake. Below are the default ports used by
the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| https | tcp | 443 |

## Roles

Roles are used by Snowflake to **control access to objects** within the organization and allow users
to perform actions against those objects. Users can have several roles granted to them, and can also
have a default role assigned. Since a user is allowed to switch roles during a session in order to
have the appropriate permissions to perform certain actions, the Snowflake app accomodates this by
having an optional 'role' parameter in each of the actions. If this parameter is left blank, the
default role assigned to the user will be used.

## Authentication

The Snowflake connector supports two authentication methods:

### 1. Password Authentication (Default)

The simplest authentication method using username and password credentials.

**Required Configuration:**

- **auth_type**: Set to "Password"
- **username**: Your Snowflake username
- **password**: Your Snowflake password

### 2. Certificate-Based Authentication (Key Pair)

Enhanced security authentication using RSA key pair for passwordless authentication.

**Required Configuration:**

- **auth_type**: Set to "Certificate Based Authentication(CBA)"
- **username**: Your Snowflake username
- **private_key**: RSA private key in PEM format
- **private_key_password**: (Optional) Password for encrypted private keys

#### Setting Up Key Pair Authentication

**Step 1: Generate RSA Key Pair**

Generate an unencrypted private key:

```bash
# Generate 2048-bit RSA private key in PKCS#8 format
openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt

# Extract public key from private key
openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub
```

**Step 2: Extract Public Key Value**

Get the public key string (remove headers and newlines):

```bash
# Display public key without headers
grep -v "BEGIN\|END" rsa_key.pub | tr -d '\n'
```

**Step 3: Assign Public Key to Snowflake User**

```sql
-- Assign the public key to your user account
ALTER USER your_username SET RSA_PUBLIC_KEY='MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...';

-- Verify the key assignment
DESCRIBE USER your_username;
```

More info can be found at [Snowflake Key Pair Authentication Documentation](https://docs.snowflake.com/en/user-guide/key-pair-auth)
