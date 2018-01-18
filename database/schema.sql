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
	biography text,
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

