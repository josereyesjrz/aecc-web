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
	ccode text not null,
	cname text not null unique
	
);

insert into courses (ccode, ccname) values ("CCOM3020", "Discrete Mathematics");
insert into courses (ccode, ccname) values ("CCOM3030", "Introduction to Computer Science");
insert into courses (ccode, ccname) values ("CCOM3033", "Introduction to Computer Programming");
insert into courses (ccode, ccname) values ("CCOM3034", "Data Structures");
insert into courses (ccode, ccname) values ("CCOM3981", "Undergraduate Seminar 1");
insert into courses (ccode, ccname) values ("CCOM3982", "Undergraduate Seminar 2");
insert into courses (ccode, ccname) values ("CCOM3986", "Undergraduate Research in Computer Science");
insert into courses (ccode, ccname) values ("CCOM4017", "Operating Systems");
insert into courses (ccode, ccname) values ("CCOM4027", "Introduction To Data Management");
insert into courses (ccode, ccname) values ("CCOM4029", "High Level Programming Languages");
insert into courses (ccode, ccname) values ("CCOM4030", "Introduction to Software Engineering");
insert into courses (ccode, ccname) values ("CCOM4065", "Numerical Linear Algebra");
insert into courses (ccode, ccname) values ("CCOM4086", "Computer Architecture I");
insert into courses (ccode, ccname) values ("CCOM4087", "Compiler Design");
insert into courses (ccode, ccname) values ("CCOM4088", "Cybersecurity");
insert into courses (ccode, ccname) values ("CCOM4205", "Computer Networks");
insert into courses (ccode, ccname) values ("CCOM4995", "Fun with Programming Interview Problems");
insert into courses (ccode, ccname) values ("CCOM4995", "Reverse Engineering");
insert into courses (ccode, ccname) values ("CCOM4995", "Systems and Network Security");
insert into courses (ccode, ccname) values ("CCOM4995", "Hardware Security");
insert into courses (ccode, ccname) values ("CCOM4995", "Competitive Programming");
insert into courses (ccode, ccname) values ("CCOM4995", "Big Data");
insert into courses (ccode, ccname) values ("CCOM4995", "Computer Graphics");
insert into courses (ccode, ccname) values ("CCOM4995", "Computer Vision");
insert into courses (ccode, ccname) values ("CCOM4995", "Parallel Programming");
insert into courses (ccode, ccname) values ("CCOM4996", "Independent Study in Computer Science");
insert into courses (ccode, ccname) values ("CCOM5026", "Computer Architecture II");
insert into courses (ccode, ccname) values ("CCOM5035", "Computability Theory");
insert into courses (ccode, ccname) values ("CCOM5045", "Introduction to Computational Cell Biology");
insert into courses (ccode, ccname) values ("CCOM5050", "Design And Analysis Of Algorithms");
insert into courses (ccode, ccname) values ("CCOM5060", "Parallel Processing");
insert into courses (ccode, ccname) values ("CCOM5677", "Artificial Intelligence");
insert into courses (ccode, ccname) values ("MATE3018", "Pre Calculus and Analytical Geometry");
insert into courses (ccode, ccname) values ("MATE3023", "Pre Calculus I");
insert into courses (ccode, ccname) values ("MATE3024", "Pre Calculus II");
insert into courses (ccode, ccname) values ("MATE3151", "Calculus I");
insert into courses (ccode, ccname) values ("MATE3152", "Calculus II");
insert into courses (ccode, ccname) values ("MATE3325", "Introduction to Discrete Mathematics");
insert into courses (ccode, ccname) values ("MATE4031", "Linear Algebra");
insert into courses (ccode, ccname) values ("MATE4061", "Numerical Analysis I");
insert into courses (ccode, ccname) values ("MATE4080", "Applied Modern Algebra");
insert into courses (ccode, ccname) values ("MATE4081", "Modern Algebra");
insert into courses (ccode, ccname) values ("MATE5001", "Probability");

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