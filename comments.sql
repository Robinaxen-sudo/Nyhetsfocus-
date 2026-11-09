-- ====== KOMMENTARER ==========================================================
-- Kör i Supabase → SQL Editor. Kräver att resten av setup.sql redan är körd.
-- (kan köras flera gånger utan att något går sönder)

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
