drop table if exists users;
create table users (
	id integer primary key autoincrement,
	email text not null,
	studentID char not null unique,
	studentFirstName text not null,
	studentLastName text not null,
	phoneNumber char(10),
	password text not null,
	salt text not null,
	priviledge text not null default "MEMBER",
	status text not null default "PENDING",
	confirmation boolean not null default 0,
	confirmed_on text default null,
	customPicture text not null default "FALSE",
	biography text,
	date_created text not null default (datetime('now'))
);

insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "president", "Jeffrey", "Chan", "0f23ce5902d8c8d5717f87b3d17069eb828c18e051a7379935c06e048ae7fb79381cc0c48dfbf00a3b8848b393bfb709a2389767ce66223860fa67a53f1c936d", "1a8b09ce7664d7bbfd191a95b97fd6c2861febedfa5d6c4f30bd49e0e7e1c06e2870be3ee642c6047f291a7177f6ba07b223029d1183e6cbd9efc355cad1445b", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "vicepresident", "Alejandro", "Vega", "2821700585e471a9f20de0ce72905135fc1ece59e0cab493a6aeac3f2090512e75f8673252044288fe7f988d1add678cc9e493f0a867fed65ee208cf647cfd25", "953baf7d7b0e8330259e276e89b72b5e184a046bd875ca740ef6017f52a7e8c9c63b05518a295abd0b0034d04daef0a8e5afa99ea6697178f74f4d965464cc36", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "treasurer", "Angelissa", "Aviles", "4e493036f87e8247de82cf89aafbb9536c07ffd72326e154675a20d1368ca7059ddde9a960deea0a1780c4e6234f3bbabbeda8a5bf5322e6e58354f1c9f1c51c", "3b9c1f0d0aa4280478532e953e702d8dcb92a745276b70fc71e6263b52c80bc0fd38285aa57617556d886eea5902c93a920d6019a047b41798c25017dcdffc9d", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "pragent", "Isamar", "López", "59ce01bff6f58ff82d5306d97aa0f8d475f3b07b42100cb7a9b0e5f466838e5e4db88c5ac57c662ed0c2d6c53d1204de5fa0df80ce4003175a8da7a637595ee3", "22abfcb3d0c7b708892b6baed4c315779a96db98f714484180e62a3591400af21b480475a64a4d2bf412c034079e5831c2aacdc53b6c9ee9c60ba78f99c11a16", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "secretary", "María", "Ramos", "354947ce44ec796acf6e6fd5585adcb8663bc2e0405d392cdc16a167ba7cc3ec9f8f4ba4550a98726261940d0605bf84c910787de61bdd542f7475d8e2a570c7", "8fae4c22dccc039e714b75fc27f2a80f95c8bfa983f424db9649e158f410f21d24122e7719a5cc53ff114d26865dfb704f6ecf66a4529431b94283acd2174e13", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "boardmember1", "Lillian", "González", "fc0213b43cee283ac64519fdfa6cafd292c039ae2fe6b47227a9723a34f00763321e785208eb16be114c79f4f19d0962062a62de7b919486432fe3c42baff99d", "5d574ddcd0670b124749e67bde92bb140978a9a6071c8726f0aa1c785715b79d675b9150191d7b406f5298fd9a1767693b1e6c8b0c11e2f6c18cdd563d7e0c64", "ADMIN", 1, datetime('now'));
insert into users (email, studentID, studentFirstName, studentLastName, password, salt, priviledge, confirmation, confirmed_on) values ("aecc.upr@gmail.com", "boardmember2", "Israel", "Dilán", "00d1c4c4a567986b63de1d83ce05e5b42ed5d4db62b7c4f8e8f43419305eea0e8745d0373a55ab611064238c533633647b80a186218eac68545f2b8d6038b142", "aac3e45d4c006d2134d59cee30518c25eb259fc3f24f5b3dbbfb864f5a7420f5967538837de67dc473915ee39b9e90a86792c21ec0dfe14bf9c419fa624d88d7", "ADMIN", 1, datetime('now'));

drop table if exists courses;
create table courses (
	cid integer primary key autoincrement,
	ccode text not null,
	ccname text not null unique
	
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