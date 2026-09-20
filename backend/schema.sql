CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT,
 google_sub TEXT UNIQUE,
 email_verified BOOLEAN NOT NULL DEFAULT FALSE,
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 avatar_url TEXT,
 bio TEXT DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS email_verifications (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE,
 expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS password_resets (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE,
 expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS novels (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 author_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title TEXT NOT NULL,
 description TEXT DEFAULT '',
 genre TEXT NOT NULL,
 cover_url TEXT DEFAULT '',
 status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','pending','published','revision')),
 review_note TEXT DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 published_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS chapters (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 novel_id UUID NOT NULL REFERENCES novels(id) ON DELETE CASCADE,
 chapter_no INTEGER NOT NULL,
 title TEXT NOT NULL,
 body TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(novel_id,chapter_no)
);

CREATE TABLE IF NOT EXISTS comments (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 novel_id UUID NOT NULL REFERENCES novels(id) ON DELETE CASCADE,
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS likes (
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 novel_id UUID NOT NULL REFERENCES novels(id) ON DELETE CASCADE,
 PRIMARY KEY(user_id,novel_id)
);

CREATE TABLE IF NOT EXISTS bookmarks (
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 novel_id UUID NOT NULL REFERENCES novels(id) ON DELETE CASCADE,
 PRIMARY KEY(user_id,novel_id)
);

CREATE TABLE IF NOT EXISTS follows (
 follower_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 following_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY(follower_id,following_id),
 CHECK(follower_id<>following_id)
);

CREATE INDEX IF NOT EXISTS novels_status_idx ON novels(status);
CREATE INDEX IF NOT EXISTS chapters_novel_idx ON chapters(novel_id,chapter_no);
CREATE INDEX IF NOT EXISTS comments_novel_idx ON comments(novel_id,created_at);
