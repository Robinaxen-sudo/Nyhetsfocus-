-- Kör hela filen i Supabase → SQL Editor → New query → Run
-- (kan köras flera gånger utan att något går sönder)

-- 1) Tabeller ---------------------------------------------------------
create table if not exists public.articles (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  summary text not null default '',
  content text not null default '',
  cat text not null default 'Nyheter',
  author text not null default 'Redaktionen',
  image text not null default '',
  date date not null default current_date,
  status text not null default 'draft' check (status in ('draft','published')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.site_settings (
  id int primary key default 1 check (id = 1),
  name text not null default 'Nyhetsfocus',
  tagline text not null default 'Nyheter, intervjuer och drama från den svenska influencervärlden',
  cats text[] not null default array['Nyheter','Intervjuer','Skvaller & drama','Influencers','Sociala medier','Politik']
);
insert into public.site_settings (id) values (1) on conflict do nothing;

create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

-- 2) Hjälpfunktion: är inloggad användare redaktör? -------------------
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;
grant execute on function public.is_admin() to anon, authenticated;

-- 3) Radnivåsäkerhet (RLS) -------------------------------------------
alter table public.articles      enable row level security;
alter table public.site_settings enable row level security;
alter table public.admins        enable row level security;

drop policy if exists "läs publicerade"   on public.articles;
drop policy if exists "redaktör läs allt" on public.articles;
drop policy if exists "redaktör skriv"    on public.articles;
create policy "läs publicerade"   on public.articles for select using (status = 'published');
create policy "redaktör läs allt" on public.articles for select to authenticated using (public.is_admin());
create policy "redaktör skriv"    on public.articles for all    to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "läs inställningar"   on public.site_settings;
drop policy if exists "redaktör inställningar" on public.site_settings;
create policy "läs inställningar"      on public.site_settings for select using (true);
create policy "redaktör inställningar" on public.site_settings for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- admins-tabellen: ingen åtkomst via API (hanteras bara härifrån)

-- 4) Bildlagring ------------------------------------------------------
insert into storage.buckets (id, name, public)
values ('nyheter', 'nyheter', true)
on conflict (id) do update set public = true;

drop policy if exists "bilder läs"   on storage.objects;
drop policy if exists "bilder skriv" on storage.objects;
create policy "bilder läs"   on storage.objects for select using (bucket_id = 'nyheter');
create policy "bilder skriv" on storage.objects for all to authenticated
  using (bucket_id = 'nyheter' and public.is_admin())
  with check (bucket_id = 'nyheter' and public.is_admin());

-- 5) TIPS & KONTAKT ----------------------------------------------------

create table if not exists public.tips (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  type text not null default 'tips' check (type in ('tips','kontakt','rattelse')),
  subject text not null default '' check (char_length(subject) <= 150),
  message text not null check (char_length(message) between 10 and 5000),
  name text not null default '' check (char_length(name) <= 100),
  email text not null default '' check (char_length(email) <= 200),
  link text not null default '' check (char_length(link) <= 500 and (link = '' or link ~* '^https?://')),
  image_path text not null default '' check (char_length(image_path) <= 200),
  status text not null default 'new' check (status in ('new','read','done')),
  ip_hash text
);

-- Spamskydd: max 5 inskick per timme och IP (IP:n sparas aldrig, bara en avidentifierad hash)
create or replace function public.tips_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  hdr json;
  ip text;
begin
  begin
    hdr := coalesce(nullif(current_setting('request.headers', true), ''), '{}')::json;
  exception when others then
    hdr := '{}'::json;
  end;
  ip := trim(split_part(coalesce(hdr->>'x-forwarded-for', hdr->>'cf-connecting-ip', ''), ',', 1));
  new.status := 'new';
  new.created_at := now();
  new.ip_hash := case when ip = '' then null else md5(ip || ':nyhetsfocus') end;
  if new.ip_hash is not null and (
    select count(*) from public.tips where ip_hash = new.ip_hash and created_at > now() - interval '1 hour'
  ) >= 5 then
    raise exception 'För många inskick just nu. Försök igen om en stund.';
  end if;
  return new;
end;
$$;

drop trigger if exists tips_guard_trg on public.tips;
create trigger tips_guard_trg before insert on public.tips
for each row execute function public.tips_guard();

alter table public.tips enable row level security;
drop policy if exists "alla får skicka tips" on public.tips;
drop policy if exists "redaktör hanterar tips" on public.tips;
create policy "alla får skicka tips" on public.tips for insert to anon, authenticated with check (true);
create policy "redaktör hanterar tips" on public.tips for all to authenticated using (public.is_admin()) with check (public.is_admin());
grant insert on public.tips to anon, authenticated;

-- Privat bildlagring för inskickade bilder (max 5 MB, bara bilder)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('tips', 'tips', false, 5242880, array['image/jpeg','image/png','image/webp','image/gif'])
on conflict (id) do update set public = false, file_size_limit = 5242880,
  allowed_mime_types = array['image/jpeg','image/png','image/webp','image/gif'];

drop policy if exists "tips bilder skicka" on storage.objects;
drop policy if exists "tips bilder redaktör" on storage.objects;
create policy "tips bilder skicka" on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'tips');
create policy "tips bilder redaktör" on storage.objects for all to authenticated
  using (bucket_id = 'tips' and public.is_admin())
  with check (bucket_id = 'tips' and public.is_admin());

-- 6) KOMMENTARER -------------------------------------------------------

create table if not exists public.comments (
  id uuid primary key default gen_random_uuid(),
  article_id uuid not null references public.articles(id) on delete cascade,
  created_at timestamptz not null default now(),
  name text not null default '' check (char_length(name) <= 50),
  body text not null check (char_length(body) between 2 and 1500),
  status text not null default 'visible' check (status in ('visible','hidden')),
  ip_hash text
);
create index if not exists comments_article_idx on public.comments (article_id, created_at);

-- Spamskydd: max 3 kommentarer per 10 minuter och IP (bara en avidentifierad hash sparas)
create or replace function public.comments_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  hdr json;
  ip text;
begin
  begin
    hdr := coalesce(nullif(current_setting('request.headers', true), ''), '{}')::json;
  exception when others then
    hdr := '{}'::json;
  end;
  ip := trim(split_part(coalesce(hdr->>'x-forwarded-for', hdr->>'cf-connecting-ip', ''), ',', 1));
  new.status := 'visible';
  new.created_at := now();
  new.ip_hash := case when ip = '' then null else md5(ip || ':nyhetsfocus') end;
  if new.ip_hash is not null and (
    select count(*) from public.comments where ip_hash = new.ip_hash and created_at > now() - interval '10 minutes'
  ) >= 3 then
    raise exception 'För många kommentarer just nu. Försök igen om en stund.';
  end if;
  return new;
end;
$$;

drop trigger if exists comments_guard_trg on public.comments;
create trigger comments_guard_trg before insert on public.comments
for each row execute function public.comments_guard();

alter table public.comments enable row level security;
drop policy if exists "läs kommentarer"      on public.comments;
drop policy if exists "skriv kommentar"      on public.comments;
drop policy if exists "redaktör kommentarer" on public.comments;

-- Alla ser synliga kommentarer på publicerade artiklar
create policy "läs kommentarer" on public.comments for select
  using (status = 'visible' and exists (select 1 from public.articles a where a.id = article_id and a.status = 'published'));
-- Alla får kommentera publicerade artiklar
create policy "skriv kommentar" on public.comments for insert to anon, authenticated
  with check (exists (select 1 from public.articles a where a.id = article_id and a.status = 'published'));
-- Redaktören får läsa, dölja och ta bort allt
create policy "redaktör kommentarer" on public.comments for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

grant select, insert on public.comments to anon, authenticated;

-- 7) GÖR DIG SJÄLV TILL REDAKTÖR --------------------------------------
-- Skapa först din användare: Authentication → Users → Add user (e-post + lösenord, bocka "Auto confirm").
-- Byt sedan e-postadressen nedan och kör raden:
--
-- insert into public.admins (user_id)
-- select id from auth.users where email = 'DIN@EPOST.SE'
-- on conflict do nothing;
