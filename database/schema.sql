drop table if exists users;
create table users (
	id integer primary key autoincrement,
	email text not null unique,
	username text not null unique,
	password text not null,
	date_created text not null
);

drop table if exists posts;
create table posts (
	id integer primary key autoincrement,
	title text not null,
	author_id integer not null,
	body text not null,
	date_created text not null
);