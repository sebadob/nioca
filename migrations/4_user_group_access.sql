DELETE FROM users;

alter table users
    drop column email;

alter table users
    drop column enc_key_id;

alter table users
    drop column token_set;

alter table users
    add oidc_id varchar not null;

alter table users
    add email varchar not null;

alter table users
    add given_name varchar;

alter table users
    add family_name varchar;

create unique index users_email_uindex
    on users (email);

create unique index users_oidc_id_uindex
    on users (oidc_id);

create table users_group_access
(
    user_id      Uuid  not null
        constraint users_group_access_users_id_fk
            references users
            on update cascade on delete cascade,
    group_id     uuid  not null
        constraint users_group_access_groups_id_fk
            references groups
            on update cascade on delete cascade,
    enc_key_id   uuid  not null
        constraint users_group_access_enc_keys_id_fk
            references enc_keys
            on update cascade on delete restrict,
    group_access bytea not null,
    constraint users_group_access_pk
        primary key (user_id, group_id)
);
