# Nioca

**CAUTION:**  
There has not been any third party security audit for this project.  
Use this software at your own risk!

**INFO:**  
This project is currently pre v1.0 and not intended for real production use yet.  
Things might change between versions until the API has been stabilized.  
However, it is working for testing and smaller setups so far.

## Project State

Even though I am using it already for my own DEV environments, this project is still in an early phase.  
The UI is not yet "prettified" and some parts and functionalities are completely missing. The basics are there and
are working fine so far. Almost everything has been prepared for the future features and options, even when they might
not be implemented yet.  
v0.4.0 is the first public release in this open source repository, but it has been used for testing and development
beforehand behind closed doors already. There is an independent `nioca-client` which can be used to easily fetch
certificates on external clients, which is especially useful for SSH. This client can be used as a standalone CLI tool
and therefore with simple system tasks on any machine, and it has a library implementation to be used from Rust apps
easily. This client is not yet public, but will get its own repo in the near future. Some work must be done before it
can be made public as well.

## What it is

Nioca is a Certificate Authority for TLS / X509 and SSH certificates.  
Its goal is to have a minimal footprint while being fast and efficient at the same time.

There has not been a third party security audit yet, but a lot of design has gone into the base setup and foundation to
be as secure as possible. Even in the case that someone might gain access to the underlying Postgres database, it should
not be able to break into the system.   
All important values are stored encrypted inside the database, while the encryption happens in-memory inside Nioca
itself. This means it should be able (after a 3rd party security audit maybe) to use Nioca even in an environment where
you could not even trust the DBA.

## How it works

Nioca implements zero trust all the way and it even does not trust the DBA by default.  
When it is started up for the very first time, you need to initialize it. You can use the same binary that starts the
server for generating X509 / SSH Certificate Authorities, full certificate chains (CA -> Intermediate -> EndEntity) and
just the EndEntity certificates themselves with the CLI.

1. For the very first start, you need to generate at least the Root + Intermediate CA on another host. The most optimal
   way of doing it would be to use an offline host with a Live OS booted into memory and saving the generated CA on an
   encrypted USB stick (for instance something like the iStorage datAshur). This might seem a bit paranoid, but that is
   the whole mindset behind Nioca's design. For testing, you can just do it on any host you like, of course.
2. After the full chain has been generated, you have all the files needed for the very first initialization.
   Just open your browser, and you will be redirected to Nioca's Initialization page where you can add all the necessary
   information.
3. The Master Shard Keys 1 + 2 must be saved from this stage. There is not a single way you can ever recover or see
   them again after this step. These keys will be used for the unsealing process.
4. When Nioca is started up (and initialized) it will be sealed by default. You need to unseal it with the 2 Master
   Key's
   from the initialization stage. From these Keys, Nioca will build up the master encryption key, which will then be
   used
   to decrypt all the other encryption keys and secrets from inside the database.
5. After Nioca has been unsealed, it can be used normally. There is only one single local root / admin user.
6. After your first login with the local root user, you can configure an SSO provider (like
   [rauthy](https://github.com/sebadob/rauthy) for instance). Daily operations should be done by Nioca Admins logged in
   via SSO.

# Prerequisites

Most things are built in and even database migrations between versions are embedded in the code.  
However, the very first database and user must exist. Create them on any postgres instance with
the following:

```sql
CREATE USER nioca WITH PASSWORD '123SuperNioca';
CREATE DATABASE nioca WITH OWNER nioca;
```

## Setup

1. Download the `nioca` binary from the `out/` directory for Linux, or (at this early stage of the project) clone this
   repo and build it yourself with `cargo build --release`

2. Generate the X509 full certificate chain and the unsealing certificates. Adjust the `--alt-name-ip` and
   `--alt-name-dns` to your needs.

```
./nioca x509 \
  --o 'My Org' \
  --alt-name-dns localhost \
  --alt-name-ip 127.0.0.1 \
  --alt-name-ip 192.168.14.50 \
  --usages digital-signature \
  --usages-ext server-auth \
  --stage full \
  --clean
```

- Enter your chosen password for the Root CA 3 times (new password, confirm, then test it afterward)
- Depending on your machine, these steps might take a while, because of a very heavy weight Argon2Id hashing behind
  the scenes to make it as secure as possible. You need at least 256MB of memory available for this operation!
- Enter your chosen password for the Intermediate CA 3 times. This should be different from the Root CA password!
- On success, you will have a full certificate chain generated in `ca/x509/`

3. To be able to start up Nioca, you will need a config first. Use `.env.deploy` from this repo as a minimal template.
   All values should be documented enough to understand, what you need to configure there.
   The `UNSEAL_CERT_B64` and `UNSEAL_KEY_B64` can be found in your newly generated CA chain folder:

- `UNSEAL_CERT_B64`: `cat ca/x509/end_entity/1/cert-chain.pem.b64`
- `UNSEAL_KEY_B64`: `cat ca/x509/end_entity/1/key.pem.b64`

4. Start the container:

- If you have a Postgres running on your localhost:

```
docker run --rm -v ./.env.deploy:/.env --network="host" sdobedev/nioca:0.4.0
```

- If you have it inside the same docker network, for instance with docker compose:

```
docker run --rm -v ./.env.deploy:/.env -p 8080:8080 -p 8443:8443 sdobedev/nioca:0.4.0
```

**Note:** Currently, this step is a bit tricky. To have a "secure" TLS connection in the browser, we MUST use port 443.
To make development simpler, this is using the `root` user inside the docker image for now. Another solution can be
found in the `justfile` where we grant a process the capabilities to bind to a port below 1024. A solution for this will
come in the future which makes it possible to run the container with a non-root user.

5. Click the link from inside the log output to get to the unseal / init UI
6. Fill out all the values, which you either know, like the encryption password for the Intermediate CA or the
   `INIT_KEY`, or you get them from the generated CA files:

- Root Certificate in PEM format: `cat ca/x509/root/root.cert.pem`
- Intermediate Certificate in PEM format: `cat ca/x509/intermediate/intermediate.cert.pem`
- Intermediate Key in encrypted PEM-HEX format: `cat ca/x509/intermediate/intermediate.key.pem.hex`
- Intermediate Key encryption password: The password for the Intermediate CA from the CA generation from step 2
- Nioca Init Key: The `INIT_KEY` from the `.env.deploy` file or the Nioca logs output
- The new password should be at least 16 characters. This is the local root user's password and grant access to
  everything.
- Click `Validate`
- If you entered all information correctly, you will see the parsed certificates and verify them before clicking
  `Initialize`
- **IMPORTANT**: Save the 2 master keys from this step in the most secure way you can think of! Preferable in 2 totally
  different locations with different access systems and / or credentials.  
  You will only see them at this stage and (at least for now) there is no way to restore or ever see them again! When
  you have saved the Master Key's, click `PROCEED`

7. After the initialization, you will see the default screen when Nioca is sealed. It will always be in this stage
   after a restart to make the whole system as tamper resistant as possible.
8. Enter the Master Keys from the initialization. The order does not matter. The by default 10 second rate limiter
   should be increased in production if possible to make it even more brute force resistant. This rate limiter is global
   and not bound to an IP or anything else. After a key has been entered, the whole Nioca application will not accept
   any
   other input from any source in the sealed state.
9. Depending on your system, the unsealing process could take a while because of the very heavy weight Argon2Id hashing.
10. After your first login, you can (and should) create an SSH CA from the navigation.
11. More in-depth readme and tutorials will follow in the future.

## Development

### sqlx compile time checked queries

If you are in DEV mode and the compilation fails because of the `sqlx::query!` macro, which complains about a not
yet applied migration (Chicken - Egg Problem), you need to install the sqlx cli to apply the migration manually beforehand.
The CLI will use the values from the `.env` file in the root folder.

`cargo install sqlx-cli`

You can then create and drop the database from the cli:

`sqlx database create`
`sqlx database drop`

And run migrations:

`sqlx migrate run`

Or a specific migration:<br>
`sqlx migrate add <name>`

# Issuing certificates via CLI - Examples

You can issue new intermediate or end entity certificates with the already existing and created Root CA.

To do so, you will need the secret keys for the private key decryption.
Without these keys, you will not be able to issue new certificates.
To create a new intermediate certificate, you need the Root CA encryption key.
To create a new end entity certificate, you need the Intermediate CA encryption key.

Note: Issuing multiple intermediate CA's is currently not supported by the current nioca CLI tool.
If you need multiple Intermediates, create a new folder and just copy the 'root' content over.

However, you can issue as many end entity certificates as you like. They will be created in subfolders.
The folder names will match their serial numbers.

### Example for issuing a new intermediate certificate:
```
nioca x509 \
    --cn 'My Common Name' \
    --c 'DE' \
    --l 'Dusseldorf' \
    --ou 'My Company - Nioca' \
    --o 'My Company' \
    --st 'NRW' \
    --stage intermediate
```

### Example for issuing an end entity certificate:
```
nioca x509 \
    --cn 'ca.example.com' \
    --c 'DE' \
    --l 'Dusseldorf' \
    --o 'My Company' \
    --st 'NRW' \
    --alt-name-ip '192.168.14.50' \
    --alt-name-dns 'ca.example.com' \
    --usages-ext server-auth \
    --usages-ext client-auth \
    --stage end-entity
```
