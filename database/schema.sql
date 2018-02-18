-- this table contains each user's info,
-- including their name, email, phone number,
-- linkedin, facebook, and git links,
-- their salted passwords, their AECC member
-- privilege, their payment status, date of
-- confirmation, profile picture and bio
drop table if exists users;
create table users (
	id integer primary key autoincrement,
	email text not null,
	studentID char not null unique,
	studentFirstName text not null,
	studentLastName text not null,
	phoneNumber char(10),
	linkedin text unique,
	gituser text unique,
	facebook text unique,
	password text not null,
	salt text not null,
	priviledge text not null default "USER",
	status text not null default "PENDING",
	memberType text default null,
	confirmation boolean not null default 0,
	customPicture text not null default "FALSE",
	biography text,
	date_created text not null default (datetime('now'))
);

-- these queries add the seven admin accounts into the users table
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, date_created) values ("jeffrey.chan@upr.edu", "president", "LEAVE", "BLANK", "0f23ce5902d8c8d5717f87b3d17069eb828c18e051a7379935c06e048ae7fb79381cc0c48dfbf00a3b8848b393bfb709a2389767ce66223860fa67a53f1c936d", "1a8b09ce7664d7bbfd191a95b97fd6c2861febedfa5d6c4f30bd49e0e7e1c06e2870be3ee642c6047f291a7177f6ba07b223029d1183e6cbd9efc355cad1445b", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, date_created) values ("alejandro.vega@upr.edu", "vicepresident", "LEAVE", "BLANK", "2821700585e471a9f20de0ce72905135fc1ece59e0cab493a6aeac3f2090512e75f8673252044288fe7f988d1add678cc9e493f0a867fed65ee208cf647cfd25", "953baf7d7b0e8330259e276e89b72b5e184a046bd875ca740ef6017f52a7e8c9c63b05518a295abd0b0034d04daef0a8e5afa99ea6697178f74f4d965464cc36", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, date_created) values ("angelissa.aviles@upr.edu", "treasurer", "LEAVE", "BLANK", "4e493036f87e8247de82cf89aafbb9536c07ffd72326e154675a20d1368ca7059ddde9a960deea0a1780c4e6234f3bbabbeda8a5bf5322e6e58354f1c9f1c51c", "3b9c1f0d0aa4280478532e953e702d8dcb92a745276b70fc71e6263b52c80bc0fd38285aa57617556d886eea5902c93a920d6019a047b41798c25017dcdffc9d", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, date_created) values ("isamar.lopez@upr.edu", "pragent", "LEAVE", "BLANK", "59ce01bff6f58ff82d5306d97aa0f8d475f3b07b42100cb7a9b0e5f466838e5e4db88c5ac57c662ed0c2d6c53d1204de5fa0df80ce4003175a8da7a637595ee3", "22abfcb3d0c7b708892b6baed4c315779a96db98f714484180e62a3591400af21b480475a64a4d2bf412c034079e5831c2aacdc53b6c9ee9c60ba78f99c11a16", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, date_created) values ("maria.ramos@upr.edu", "secretary", "LEAVE", "BLANK", "354947ce44ec796acf6e6fd5585adcb8663bc2e0405d392cdc16a167ba7cc3ec9f8f4ba4550a98726261940d0605bf84c910787de61bdd542f7475d8e2a570c7", "8fae4c22dccc039e714b75fc27f2a80f95c8bfa983f424db9649e158f410f21d24122e7719a5cc53ff114d26865dfb704f6ecf66a4529431b94283acd2174e13", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, date_created) values ("lillian.gonzalez@upr.edu", "boardmember1", "LEAVE", "BLANK", "fc0213b43cee283ac64519fdfa6cafd292c039ae2fe6b47227a9723a34f00763321e785208eb16be114c79f4f19d0962062a62de7b919486432fe3c42baff99d", "5d574ddcd0670b124749e67bde92bb140978a9a6071c8726f0aa1c785715b79d675b9150191d7b406f5298fd9a1767693b1e6c8b0c11e2f6c18cdd563d7e0c64", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, date_created) values ("israel.dilan@upr.edu", "boardmember2", "LEAVE", "BLANK", "00d1c4c4a567986b63de1d83ce05e5b42ed5d4db62b7c4f8e8f43419305eea0e8745d0373a55ab611064238c533633647b80a186218eac68545f2b8d6038b142", "aac3e45d4c006d2134d59cee30518c25eb259fc3f24f5b3dbbfb864f5a7420f5967538837de67dc473915ee39b9e90a86792c21ec0dfe14bf9c419fa624d88d7", "ADMIN", 1, datetime('now'));

-- this table contains the codification
-- and name of CCOM and MATE courses that
-- users can specify they've taken
drop table if exists courses;
create table courses (
	cid integer primary key autoincrement,
	ccode text not null,
	ccname text not null unique
);

-- these queries add the CCOM and MATE courses into the courses table
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

drop table if exists courses_taken;
create table courses_taken (
	uid integer not null,
	cid integer not null,
	foreign key (uid) references users(id) on delete cascade,
	foreign key (cid) references courses(cid),
	primary key(uid,cid)
);

-- this table contains the transactions made by users
-- when they pay for their membership. it includes the
-- user's id, the date of transaction, the transaction token,
-- and the type of membership the user paid for
drop table if exists transactions;
create table transactions (
	tid integer primary key autoincrement,
	uid integer,
	tdate text not null,
	token text not null unique,
	foreign key (uid) references users(id)
);

-- this table contains the manual activations done by admins
-- in the case a member paid with cash. includes the user's id,
-- the id of the admin that approved the member, the date of 
-- the activation, and the type of membership the user paid for
drop table if exists manual_activations;
create table manual_activations (
	tid integer primary key autoincrement,
	uid integer,
	aid integer,
	tdate text not null,
	membertype text not null,
	foreign key (uid) references users(id),
	foreign key (aid) references users(id)
);

-- this table contains the various events the AECC will
-- carry about. includes the event's id, the event's date
-- and location, the event's title, and a description of the event
drop table if exists events;
create table events (
	eid integer primary key autoincrement,
	edate text not null,
	etitle text not null,
	elocation text not null,
	edescription text not null
);

-- this table contains the possible majors users can specify
-- when registering. right now it has the CCOM and MATE majors,
-- with an Other entry for other possible majors. could be expanded
-- if needed.
drop table if exists majors;
create table majors (
	mid integer primary key autoincrement,
	mname text not null
);

-- this table contains majors of each user
-- as specified when they register
-- uid references user's id
-- mid references major's id
drop table if exists user_majors;
create table user_majors (
	uid integer not null,
	mid integer not null,
	foreign key (uid) references users(id) on delete cascade,
	foreign key (mid) references majors(mid),
	primary key(uid)
);

-- these queries add the CCOM and MATE majors into
-- the corresponding table
insert into majors (mname) values ("Computer Science");
insert into majors (mname) values ("Mathematics");
insert into majors (mname) values ("Pure Mathematics");
insert into majors (mname) values ("Discrete Mathematics");
insert into majors (mname) values ("Computational Mathematics");
insert into majors (mname) values ("Biology");
insert into majors (mname) values ("Physics");
insert into majors (mname) values ("Chemistry");
insert into majors (mname) values ("Interdisciplinary Studies");
insert into majors (mname) values ("Nutrition and Dietetics");
insert into majors (mname) values ("Environmental Science");
insert into majors (mname) values ("Other");

-- TEST USERS
insert into users (email, studentID, studentFirstName, studentLastName, phoneNumber, password, salt, status, memberType, confirmation, date_created) values ("victor.morales12@upr.edu", "801144540", "Víctor", "Morales", "9394016059", "0f23ce5902d8c8d5717f87b3d17069eb828c18e051a7379935c06e048ae7fb79381cc0c48dfbf00a3b8848b393bfb709a2389767ce66223860fa67a53f1c936d", "1a8b09ce7664d7bbfd191a95b97fd6c2861febedfa5d6c4f30bd49e0e7e1c06e2870be3ee642c6047f291a7177f6ba07b223029d1183e6cbd9efc355cad1445b", "SUSPENDED", "ACM", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, phoneNumber, password, salt, status, memberType, confirmation, date_created) values ("eddie.cabrera@upr.edu", "801130844", "Eddie", "Cabrera", "7877877878", "2821700585e471a9f20de0ce72905135fc1ece59e0cab493a6aeac3f2090512e75f8673252044288fe7f988d1add678cc9e493f0a867fed65ee208cf647cfd25", "953baf7d7b0e8330259e276e89b72b5e184a046bd875ca740ef6017f52a7e8c9c63b05518a295abd0b0034d04daef0a8e5afa99ea6697178f74f4d965464cc36", "MEMBER", "AECC", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, phoneNumber, password, salt, status, confirmation, date_created) values ("john.wilson@upr.edu", "801000000", "John", "Wilson", "7870000000", "4e493036f87e8247de82cf89aafbb9536c07ffd72326e154675a20d1368ca7059ddde9a960deea0a1780c4e6234f3bbabbeda8a5bf5322e6e58354f1c9f1c51c", "3b9c1f0d0aa4280478532e953e702d8dcb92a745276b70fc71e6263b52c80bc0fd38285aa57617556d886eea5902c93a920d6019a047b41798c25017dcdffc9d", "PENDING", 1, datetime('now'));
-- TEST USERS FOR ABOUT PAGE
insert into users (email, studentID, studentFirstName, studentLastName, phoneNumber, password, salt, status, memberType, confirmation, date_created) values ("jeffrey.chan@upr.edu", "801124540", "Jeffrey", "Chan", "9390016059", "0f23ce5902d8c8d5717f87b3d17069eb828c18e051a7379935c06e048ae7fb79381cc0c48dfbf00a3b8848b393bfb709a2389767ce66223860fa67a53f1c936d", "1a8b09ce7664d7bbfd191a95b97fd6c2861febedfa5d6c4f30bd49e0e7e1c06e2870be3ee642c6047f291a7177f6ba07b223029d1183e6cbd9efc355cad1445b", "MEMBER", "ACM", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, phoneNumber, password, salt, status, memberType, confirmation, date_created) values ("alejandro.vega@upr.edu", "801134844", "Alejandro", "Vega", "2877877878", "2821700585e471a9f20de0ce72905135fc1ece59e0cab493a6aeac3f2090512e75f8673252044288fe7f988d1add678cc9e493f0a867fed65ee208cf647cfd25", "953baf7d7b0e8330259e276e89b72b5e184a046bd875ca740ef6017f52a7e8c9c63b05518a295abd0b0034d04daef0a8e5afa99ea6697178f74f4d965464cc36", "MEMBER", "AECC", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, phoneNumber, password, salt, status, confirmation, date_created) values ("angelissa.aviles@upr.edu", "801020000", "Angelissa", "Aviles", "7870001000", "4e493036f87e8247de82cf89aafbb9536c07ffd72326e154675a20d1368ca7059ddde9a960deea0a1780c4e6234f3bbabbeda8a5bf5322e6e58354f1c9f1c51c", "3b9c1f0d0aa4280478532e953e702d8dcb92a745276b70fc71e6263b52c80bc0fd38285aa57617556d886eea5902c93a920d6019a047b41798c25017dcdffc9d", "MEMBER", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, phoneNumber, password, salt, status, memberType, confirmation, date_created) values ("isamar.lopez@upr.edu", "801124240", "Isamar", "López", "9320216059", "0f23ce5902d8c8d5717f87b3d17069eb828c18e051a7379935c06e048ae7fb79381cc0c48dfbf00a3b8848b393bfb709a2389767ce66223860fa67a53f1c936d", "1a8b09ce7664d7bbfd191a95b97fd6c2861febedfa5d6c4f30bd49e0e7e1c06e2870be3ee642c6047f291a7177f6ba07b223029d1183e6cbd9efc355cad1445b", "MEMBER", "ACM", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, phoneNumber, password, salt, status, memberType, confirmation, date_created) values ("maria.ramos@upr.edu", "802114844", "María", "Ramos", "2817847878", "2821700585e471a9f20de0ce72905135fc1ece59e0cab493a6aeac3f2090512e75f8673252044288fe7f988d1add678cc9e493f0a867fed65ee208cf647cfd25", "953baf7d7b0e8330259e276e89b72b5e184a046bd875ca740ef6017f52a7e8c9c63b05518a295abd0b0034d04daef0a8e5afa99ea6697178f74f4d965464cc36", "MEMBER", "AECC", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, phoneNumber, password, salt, status, confirmation, date_created) values ("lillian.gonzalez@upr.edu", "801023200", "Lillian", "González", "7873201000", "4e493036f87e8247de82cf89aafbb9536c07ffd72326e154675a20d1368ca7059ddde9a960deea0a1780c4e6234f3bbabbeda8a5bf5322e6e58354f1c9f1c51c", "3b9c1f0d0aa4280478532e953e702d8dcb92a745276b70fc71e6263b52c80bc0fd38285aa57617556d886eea5902c93a920d6019a047b41798c25017dcdffc9d", "MEMBER", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, phoneNumber, password, salt, status, memberType, confirmation, date_created) values ("israel.dilan@upr.edu", "801124140", "Israel", "Dilán", "9330012059", "0f23ce5902d8c8d5717f87b3d17069eb828c18e051a7379935c06e048ae7fb79381cc0c48dfbf00a3b8848b393bfb709a2389767ce66223860fa67a53f1c936d", "1a8b09ce7664d7bbfd191a95b97fd6c2861febedfa5d6c4f30bd49e0e7e1c06e2870be3ee642c6047f291a7177f6ba07b223029d1183e6cbd9efc355cad1445b", "MEMBER", "ACM", 1, datetime('now'));

insert into user_majors (uid, mid) values (8, 2);
insert into user_majors (uid, mid) values (9, 2);
insert into user_majors (uid, mid) values (10, 2);
insert into user_majors (uid, mid) values (11, 2);
insert into user_majors (uid, mid) values (12, 2);
insert into user_majors (uid, mid) values (13, 2);
insert into user_majors (uid, mid) values (14, 2);
insert into user_majors (uid, mid) values (15, 2);
insert into user_majors (uid, mid) values (16, 2);
insert into user_majors (uid, mid) values (17, 2);