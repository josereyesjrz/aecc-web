drop table if exists users;
create table users (
	id integer primary key autoincrement,
	email text not null unique,
	studentID char(9) not null unique,
	studentFirstName text not null,
	studentLastName text not null,
	phoneNumber char(10) not null unique,
	password text not null,
	priviledge text not null default "MEMBER",
	status text not null default "PENDING",
	customPicture text not null default "FALSE",
	biography text,
	date_created text not null
);

drop table if exists courses;
create table courses (
	cid integer primary key autoincrement,
	cname text not null unique,
	ccode text not null
);



-- drop table if exists posts;
-- create table posts (
-- 	id integer primary key autoincrement,
-- 	title text not null,
-- 	author_id integer not null,
-- 	body text not null,
-- 	date_created text not null
-- );

drop table if exists transactions;
create table transactions (
	tid integer primary key autoincrement,
	uid integer,
	tdate text not null,
	token text not null unique,
	foreign key (uid) references users(id)
);

drop table if exists events;
create table events (
	eid integer primary key autoincrement,
	edate text not null,
	etitle text not null,
	elocation text not null,
	edescription text not null
);