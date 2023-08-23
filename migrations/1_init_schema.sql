create table sealed
(
    id            uuid                     not null
        constraint sealed_pk
            primary key,
    timestamp     timestamp with time zone not null,
    direct_access boolean                  not null,
    url           varchar                  not null
);

create table enc_keys
(
    id    uuid    not null
        constraint enc_keys_pk
            primary key,
    alg   varchar not null,
    value bytea   not null
);

create table master_key
(
    id    varchar not null
        constraint master_key_pk
            primary key,
    value varchar
);

create table users
(
    id         uuid    not null
        constraint users_pk
            primary key,
    email      varchar not null,
    enc_key_id uuid
        constraint users_enc_keys_id_fk
            references enc_keys,
    token_set  bytea
);

create index users_email_index
    on users (email);

create table ca_certs_x509
(
    id         uuid    not null,
    typ        varchar not null,
    constraint ca_certs_pk
        primary key (id, typ),
    name       varchar not null,
    expires    timestamp with time zone,
    data       varchar not null,
    fingerprint bytea,
    enc_key_id uuid    not null
        constraint ca_certs_enc_keys_id_fk
            references enc_keys
);

create table sessions
(
    id            uuid                     not null
        constraint sessions_pk
            primary key,
    local         boolean                  not null,
    created       timestamp with time zone not null,
    expires       timestamp with time zone not null,
    xsrf          varchar                  not null,
    authenticated boolean default false    not null,
    user_id       uuid
        constraint sessions_users_id_fk
            references users,
    email         varchar,
    roles         varchar,
    groups        varchar,
    is_admin      boolean,
    is_user       boolean
);

create index sessions_expires_index
    on sessions (expires);

create table config
(
    key        varchar not null
        constraint config_pk
            primary key,
    enc_key_id uuid    not null
        constraint config_enc_keys_id_fk
            references enc_keys,
    value      bytea   not null
);

create table ca_certs_ssh
(
    id         uuid    not null
        constraint ca_certs_ssh_pk
            primary key,
    name       varchar not null,
    pub_key    varchar not null,
    data       bytea   not null,
    enc_key_id uuid    not null
        constraint ca_certs_ssh_enc_keys_id_fk
            references enc_keys
);

create table groups
(
    id          uuid                 not null
        constraint groups_pk
            primary key,
    name        varchar              not null,
    enabled     boolean default true not null,
    ca_ssh      uuid
        constraint groups_ca_certs_ssh_id_fk
            references ca_certs_ssh,
    ca_x509     uuid,
    ca_x509_typ varchar default 'certificate'::character varying,
    constraint groups_ca_certs_x509_id_typ_fk
        foreign key (ca_x509, ca_x509_typ) references ca_certs_x509
);

create index groups_name_index
    on groups (name);

create table clients_ssh
(
    id                      uuid                 not null
        constraint clients_ssh_pk
            primary key,
    name                    varchar              not null,
    expires                 timestamp with time zone,
    enabled                 boolean default true not null,
    api_key                 bytea                not null,
    enc_key_id              uuid                 not null
        constraint clients_ssh_enc_keys_id_fk
            references enc_keys,
    key_alg                 varchar              not null,
    group_id                uuid                 not null
        constraint clients_ssh_groups_id_fk
            references groups,
    typ                     varchar              not null,
    principals              varchar              not null,
    force_command           varchar,
    source_addresses        varchar,
    permit_x11_forwarding   boolean,
    permit_agent_forwarding boolean,
    permit_port_forwarding  boolean,
    permit_pty              boolean,
    permit_user_rc          boolean,
    valid_secs              integer              not null,
    latest_cert             integer
);

create table certs_x509
(
    serial    serial
        constraint certs_x509_pk
            primary key,
    id        uuid                                   not null,
    created   timestamp with time zone default now() not null,
    expires   timestamp with time zone               not null,
    client_id uuid,
    user_id   uuid
        constraint certs_x509_users_id_fk
            references users
            on update cascade on delete cascade,
    data      bytea                                  not null
);

create table clients_x509
(
    id                  uuid                 not null
        constraint clients_x509_pk
            primary key,
    name                varchar              not null,
    expires             timestamp with time zone,
    enabled             boolean default true not null,
    group_id uuid not null
        constraint clients_x509_groups_id_fk
            references groups,
    api_key             bytea                not null,
    enc_key_id          uuid                 not null
        constraint clients_x509_enc_keys_id_fk
            references enc_keys
            on update cascade on delete restrict,
    key_alg             varchar              not null,
    common_name         varchar              not null,
    country             varchar,
    locality            varchar,
    organizational_unit varchar,
    organization        varchar,
    state_or_province   varchar,
    alt_names_dns       varchar              not null,
    alt_names_ip        varchar              not null,
    key_usage           bytea,
    key_usage_ext       bytea,
    valid_hours         integer              not null,
    email               varchar              not null,
    latest_cert         integer
        constraint clients_x509_certs_serial_fk
            references certs_x509
            on update cascade on delete cascade
);

create index clients_x509_name_index
    on clients_x509 (name);

create index clients_x509_email_index
    on clients_x509 (email);

create index certs_x509_expires_index
    on certs_x509 (expires desc);

create index certs_x509_id_index
    on certs_x509 (id desc);

create table certs_ssh
(
    serial    serial
        constraint certs_ssh_pk
            primary key,
    id        uuid                                   not null,
    created   timestamp with time zone default now() not null,
    expires   timestamp with time zone               not null,
    client_id uuid
        constraint certs_ssh_clients_ssh_id_fk
            references clients_ssh,
    user_id   uuid
        constraint certs_ssh_users_id_fk
            references users
            on update cascade on delete cascade,
    data      bytea                                  not null
);

alter table clients_ssh
    add constraint clients_ssh_certs_serial_fk
        foreign key (latest_cert) references certs_ssh;

create index certs_ssh_expires_index
    on certs_ssh (expires desc);

create index certs_ssh_id_index
    on certs_ssh (id desc);
