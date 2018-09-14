drop table if exists ip;
create table if not exists ip (
    ip text not null
  , ban int not null check(ban in (0, 1))
  , ts datetime not null
  , toml text
  , rbl text
  , log text
);
drop index if exists ip_i;
create unique index ip_i on ip(ip, ban);
-- vim: ts=2 expandtab
