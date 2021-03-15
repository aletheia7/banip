drop table if exists rlog;
create table if not exists rlog (
    score real not null
  , max_score real not null
    -- mime from
  , mfrom text not null
  , ip text
    -- brackets ommitted, unique_id
    -- uid is not unique
  , uid text not null
  , t datetime not null
    -- boolean 
  , is_spam int not null
  -- values changes
  -- no action: no, soft reject: soft, reject: reject, add header: junk, greylist: grey
  , action text not null
  , forced_action text not null
  , mid text not null
  , user text
  , smtp_from text not null 
  , smtp_rcpts text not null
  , subject text not null
    -- ASN ssp
  , asn text not null
    -- ASN ssp
  , ipnet text not null
    -- ASN ssp
  , country not null
    -- symbols_scores_params
  , ssp text not null
  , len int not null
  , time_real text not null
  , time_virtual text not null
  , dns_req int not null
  , digest text not null
  , mime_rcpts text not null
  , filename text null
    -- brackets ommited
  , qid text
  , settings_id text
  , cursor text not null unique
);

drop index if exists i_a_t;
create index if not exists i_a_t  on rlog(action, t);
--create index if not exists i_a_t  on rlog(action, datetime(t,'localtime'));

drop view if exists reject;
create view if not exists reject as
  select rowid, ip, datetime(t, 'localtime') t, mid
  from rlog where action = 'reject' order by datetime(t, 'localtime');

drop view if exists good;
create view if not exists good as
  select rowid, ip, datetime(t, 'localtime') t, mid
  from rlog where action = 'no' order by datetime(t, 'localtime');

drop view if exists rsum;
create view if not exists rsum as 
  select action, printf("%,6d", count(*)) ct, printf("%.2f%", count(*) / (select cast(count(*) as real) from rlog) * 100 ) percent
  from rlog group by action;

-- vim: expandtab tabstop=2
