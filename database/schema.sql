drop table if exists users;
create table users (
	u_id integer primary key autoincrement,
	email text not null unique,
	-- username text not null unique,
	first_name text not null,
	last_name text not null,
	password text not null,
	date_created text not null,
	pay_status integer not null,
);

drop table if exists posts;
create table posts (
	p_id integer primary key autoincrement,
	title text not null,
	author_id integer not null,
	body text not null,
	date_created text not null
);

drop table if exists courses;
create table courses (
	c_id integer primary key autoincrement,
	c_code text not null,
	c_name text not null,
);

-- foreign key stuff
drop table if exists courses_taken;
create table courses_taken (
	c_id integer references courses(c_id),
	u_id integer references courses(u_id),
);

-- falta events, attendance per event