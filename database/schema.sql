drop table if exists users;
create table users (
	id integer primary key autoincrement,
	email text not null,
	studentID char not null unique,
	studentFirstName text not null,
	studentLastName text not null,
	phoneNumber char(10),
	password text not null,
	priviledge text not null default "MEMBER",
	status text not null default "PENDING",
	confirmation boolean not null default 0,
	confirmed_on text default null,
	customPicture text not null default "FALSE",
	biography text,
	date_created text not null default (datetime('now'))
);

-- DEFAULT ADMIN PASSWORD: aecc-website
insert into users (email, studentID, studentFirstName, studentLastName, password, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "president", "Jeffrey", "Chan", "$5$rounds=535000$y.MIW5VCLNduVYEG$3YVtYkfSAEOF39OYPnP6qUdQypw5m4pO5ch8rR8bno0", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "vicepresident", "Alejandro", "Vega", "$5$rounds=535000$y.MIW5VCLNduVYEG$3YVtYkfSAEOF39OYPnP6qUdQypw5m4pO5ch8rR8bno0", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "treasurer", "Angelissa", "Aviles", "$5$rounds=535000$y.MIW5VCLNduVYEG$3YVtYkfSAEOF39OYPnP6qUdQypw5m4pO5ch8rR8bno0", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "pragent", "Isamar", "López", "$5$rounds=535000$y.MIW5VCLNduVYEG$3YVtYkfSAEOF39OYPnP6qUdQypw5m4pO5ch8rR8bno0", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "secretary", "María", "Ramos", "$5$rounds=535000$y.MIW5VCLNduVYEG$3YVtYkfSAEOF39OYPnP6qUdQypw5m4pO5ch8rR8bno0", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "boardmember1", "Lillian", "González", "$5$rounds=535000$y.MIW5VCLNduVYEG$3YVtYkfSAEOF39OYPnP6qUdQypw5m4pO5ch8rR8bno0", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "boardmember2", "Israel", "Dilán", "$5$rounds=535000$y.MIW5VCLNduVYEG$3YVtYkfSAEOF39OYPnP6qUdQypw5m4pO5ch8rR8bno0", "ADMIN", 1, datetime('now'));


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