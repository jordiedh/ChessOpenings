import dotenv from 'dotenv'
if (process.env.NODE_ENV !== "production") {
	dotenv.config()
}

// Import all libraries.
import express from 'express';
import nodemailer from 'nodemailer';
import path from 'path';
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'url';
import bodyParser from 'body-parser';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { Chess } from 'chess.js';
import passport from 'passport';
import redis from 'redis';
import RedisStore from 'connect-redis';
import session from 'express-session';
import flash from 'express-flash';
import methodOverride from 'method-override';
import cookieParser from 'cookie-parser';
import initializePassport from './passport-config.js'
import crypto from 'crypto';

// Initialise the passport configuration with methods find user by email/ID
initializePassport(passport, email => findUserByEmail(email), id => findUserById(id))

var db;

// SMTP details
const transporter = nodemailer.createTransport({
	host: process.env.host,
	port: process.env.port,
	secure: false,
	auth: {
		user: process.env.user,
		pass: process.env.pass
	}
})

// Send email with link to activate account
async function sendActivationLink(email, code) {
	console.log("Sending verification email")
	let info = await transporter.sendMail({
		from: "Chess Openings <jhchessopenings@gmail.com>",
		to: email,
		subject: "Verify Your Account",
		text: "Hi, please follow the below link to confirm registration of your account on Chess Openings.\n\nhttp://localhost:8000/verify?code=" + code + "\n\nIf you did not request this code, you can ignore this email."
	})
}

// Search database for user and return null if not found, or a JSON of the users db stored information if found.
// One function for email:

async function findUserByEmail(email) {
	var result = await db.get(`SELECT * FROM users WHERE email = ?`, [email])
	if (result == null) {
		return result;
	}
	return {
		id: result.id,
		username: result.username,
		email: result.email,
		password: result.password,
		permissionLevel: result.permissionLevel,
		joinedAt: result.joinedAt,
		lastSeen: result.lastSeen,
		isVerified: result.isVerified,
		verifyCode: result.verifyCode
	}


}

// One for ID, identical, just searches differently:

async function findUserById(id) {
	var result = await db.get(`SELECT * FROM users WHERE id = ?`, [id]);
	if (result == null) {
		return result;
	}
	return {
		id: result.id,
		username: result.username,
		email: result.email,
		password: result.password,
		permissionLevel: result.permissionLevel,
		joinedAt: result.joinedAt,
		lastSeen: result.lastSeen,
		isVerified: result.isVerified,
		verifyCode: result.verifyCode
	}

}

function findUserByIdNotAsync(id) {
	db.get(`SELECT * FROM users WHERE id = ?`, [id]).then(result => {
		if (result == null) {
			return result;
		}
		return {
			id: result.id,
			username: result.username,
			email: result.email,
			password: result.password,
			permissionLevel: result.permissionLevel,
			joinedAt: result.joinedAt,
			lastSeen: result.lastSeen,
			isVerified: result.isVerified,
			verifyCode: result.verifyCode
		}
	});
}

// Open redis client.

const redisClient = redis.createClient({
	host: '127.0.0.1',
	port: 6379,
});
// Connect and display any connection errors.
redisClient.connect().catch(console.error)
redisClient.on('error', function (err) {
	console.log('Could not establish a connection with redis. ' + err);
});
redisClient.on('connect', function (err) {
	console.log('Connected to redis successfully');
});

// Initialise the express app.
const app = express();
let port = 8000;

// Open the sqlite db.
(async () => {
	db = await open({
		filename: "./db.db",
		driver: sqlite3.Database
	})
})()

// Express settings.
const __filename = fileURLToPath(
	import.meta.url); // Get the directory URL

app.set('view engine', 'ejs'); // Set webpages to run from EJS
app.use(express.static(path.dirname(__filename) + '/public')); // Set the public view folder to /public (to get images, css, etc.)
app.use(bodyParser.json()); // Use the JSON bodyParser (no longer built into express)
app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(flash()) // Session storage
app.use(passport.initialize()) // Login storage
app.use(methodOverride('_method')) // Delete method for posting the logout method
app.use(cookieParser(process.env.SESSION_SECRET))
app.use(session({
	resave: false,
	saveUninitialized: false,
	store: new RedisStore({
		client: redisClient
	}),
	secret: process.env.SESSION_SECRET,
	cookie: {
		secure: false, // if true only transmit cookie over https
		httpOnly: true, // if true prevent client side JS from reading the cookie
	}
}))

// Run init function, currently empty but may need for the future (was used during debugging)
init();

// initialise function
function init() {
	
}

// Update the database to display their last seen time, probably better off storing this locally and pushing
// changes every x amount of time
function updateLastSeen(userId) {
	try {
		db.run("UPDATE users SET lastSeen = ? WHERE id = ?", [Date.now(), userId]);
		return true;
	} catch (e) {
		console.error(e)
	}
}

// Routing for pages.
app.get('/', async (req, res) => {
	
	// Find the user and pass it through to the page
	var user = null;
	if (req.session.passport) {
		if (req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if (user != null) updateLastSeen(user.id)
	
	let unread = 0;

	if (user != null) {
		updateLastSeen(user.id)
		unread = await getUnreadMessagesCount(user.id)
	}

	res.render('home', {
		user: user,
		unread: unread
	})

})

// This page has checkAuthenticated, meaning the user won't be able to access the page if they aren't
// logged in
app.get('/preferences', checkAuthenticated, async (req, res) => {
	var user = null;
	if (req.session.passport) {
		if (req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if (user != null) updateLastSeen(user.id)
	let unread = await getUnreadMessagesCount(user.id)

	res.render('preferences', {
		user: user,
		unread: unread
	})

})

app.get('/users', checkAuthenticated, async (req, res) => {
	var user = null;
	if (req.session.passport) {
		if (req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if (user != null) updateLastSeen(user.id)
	let unread = await getUnreadMessagesCount(user.id)

	// Kick user off page if they're not an Admin.
	// Redirect to 404 page once made?
	if (user.permissionLevel < 100) {
		res.redirect("/")
		return;
	}

	let users = await db.all("SELECT * FROM users");

	res.render('users', {
		user: user,
		unread: unread,
		users: users,
		formatDate: formatDate
	})

})

app.get('/account', checkAuthenticated, async (req, res) => {
	var user = null;
	if (req.session.passport) {
		if (req.session.passport.user) user = await findUserById(req.session.passport.user)
	}

	// Update last seen if the user exists.
	if (user != null) updateLastSeen(user.id)
	
	let unread = await getUnreadMessagesCount(user.id)

	res.render('account', {
		user: user,
		unread: unread
	})

})

app.get('/unverified', async (req, res) => {
	var user = null;
	if (req.session.passport) {
		if (req.session.passport.user) user = await findUserById(req.session.passport.user)
	}

	if(user == null) {
		res.redirect('/register'); 
		return; 
	}

	// Update last seen if the user exists.
	let unread = 0;

	if (user != null) {
		updateLastSeen(user.id)
		unread = await getUnreadMessagesCount(user.id)
	}

	res.render('unverified', {
		user: user,
		unread: unread
	})

})

app.get('/lab', checkAuthenticated, async (req, res) => {
	var user = null;
	if (req.session.passport) {
		if (req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if (user != null) updateLastSeen(user.id);
	let unread = await getUnreadMessagesCount(user.id)

	
	let selectedOpening = req.query.opening;

	// Query openings for user to be able edit.
	// If perm level = Admin, it will show shared public ones too.
	if (selectedOpening == null) {
		var userOpenings = null;
		if (user.permissionLevel < 100) userOpenings = await db.all("SELECT * FROM openings WHERE active = 1 AND userId = " + user.id)
		else userOpenings = await db.all("SELECT * FROM openings WHERE active = 1 AND (userId = " + user.id + " OR shared = 1)")

		res.render('lab', {
			user: user,
			unread: unread,
			userOpenings: userOpenings
		})

	// If the user has selected an opening
	} else {


		/*
		ERROR CODES

		1
			Opening does not exist
		2
			User cannot access this opening
		3
			Opening has no moves (or does not exist)

		*/
		var opening = null;
		opening = await db.get("SELECT * FROM openings WHERE id = ?", [selectedOpening])

		// If opening does not exist, no need to check for ID is number.
		if (opening == null) {
			res.redirect('/openingselection?error=1');
			return;
		}

		// If the opening doesn't belong to the user (or is public and user is not admin), error!
		if ((opening.shared == 1 && user.permissionLevel < 100) || opening.userId != user.id) {
			res.redirect('/openingselection?error=2');
			return;
		}

		var moves = null;
		moves = await db.all(`SELECT * FROM moves WHERE openingId = ?`, [selectedOpening])

		res.render('labedit', {
			user: user,
			unread: unread,
			userOpenings: userOpenings,
			opening: opening,
			moves: moves
		})
	}
})

app.get('/practice', checkAuthenticated, async (req, res) => {
	var user = null;
	if (req.session.passport) {
		if (req.session.passport.user) user = await findUserById(req.session.passport.user)
	}

	if (user != null) updateLastSeen(user.id)

	let unread = await getUnreadMessagesCount(user.id)

	var openingId = req.query.opening;

	// If opening not selected
	if (openingId == null) {
		res.redirect("/openingselection?error=3")
		return;
	}

	let opening = await db.get(`SELECT * FROM openings WHERE id=?`, [openingId])

	// If opening seleted isn't found
	if (opening == null) {
		res.redirect("/openingselection?error=3")
		return;
	}

	let moves = await db.all(`SELECT * FROM moves WHERE openingId=?`, [openingId])

	// If opening has no moves added
	if (moves.length == 0) {
		res.redirect("/openingselection?error=3")
		return;
	}

	res.render('practice', {
		Chess: Chess,
		user: user,
		unread: unread,
		opening: opening,
		moves: moves
	})

})

app.get('/labnew', checkAuthenticated, async (req, res) => {
	var user = null;
	if (req.session.passport) {
		if (req.session.passport.user) user = await findUserById(req.session.passport.user)
	}

	if (user != null) updateLastSeen(user.id)

	let unread = await getUnreadMessagesCount(user.id)

	let error = req.query.error;

	res.render('labnew', {
		user: user,
		unread: unread,
		error: error
	})

})

app.get('/openingselection', checkAuthenticated, async (req, res) => {
	var user = null;
	if (req.session.passport) {
		if (req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if (user != null) updateLastSeen(user.id)
	
	let unread = await getUnreadMessagesCount(user.id)
	let error = req.query.error;
	let errorText = null
	if(error != null) {
		if(error == 3) errorText = "This opening has no moves, please use the opening lab to start adding some."
	}

	// Separate objects so its easier to organise them into lists, rather than using the html to sort
	let siteOpenings = await db.all("SELECT * FROM openings WHERE active = 1 AND shared = 1")
	let userOpenings = await db.all("SELECT * FROM openings WHERE active = 1 AND userId = " + user.id)

	res.render('openingselection', {
		user: user,
		unread: unread,
		error: errorText,
		siteOpenings: siteOpenings,
		userOpenings: userOpenings
	})

})

app.get('/login', checkNotAuthenticated, async (req, res) => {

	var user = null;

	if (req.session.passport) {

		if (req.session.passport.user) user = await findUserById(req.session.passport.user)

	}

	let unread = 0;

	if (user != null) {
		updateLastSeen(user.id)
		unread = await getUnreadMessagesCount(user.id)
	}

	res.render('login', {
		
		user: user,
		unread: unread

	})

})

app.get('/register', checkNotAuthenticated, async (req, res) => {

	let user = null;
	let unread = 0;
	let error = req.query.error;

	res.render('register', {
		
		user: user,
		unread: unread,
		error: error

	})

})

app.get('/messages', checkAuthenticated, async (req, res) => {

	var user = null;

	if (req.session.passport) {

		if (req.session.passport.user) user = await findUserById(req.session.passport.user)

	}

	if (user != null) updateLastSeen(user.id)
	let unread = await getUnreadMessagesCount(user.id)

	let unreadMessagesSQL = await db.all(`SELECT id, replyTo FROM messages WHERE id NOT IN (SELECT messageId FROM readReceipts WHERE userId=${user.id})`)
	let unreadMessages = []
	unreadMessagesSQL.forEach(entry => {

		if(entry.replyTo != null) unreadMessages.push(entry.replyTo)
		else unreadMessages.push(entry.id)

	})
	let scope = req.query.message;

	// If they are just looking at the messages overview
	if(scope == null) {

		let messages = await db.all(`SELECT messages.*, users.username AS senderUsername, users.permissionLevel AS senderPermissionLevel FROM messages LEFT JOIN users ON sender=users.id WHERE sender = ${user.id} OR receiver = ${user.id} OR receiver = "ALL" ORDER BY sentTime DESC`);

		res.render('messages', {
			
			user: user,
			unread: unread,
			messages: messages,
			unreadMessages: unreadMessages,
			formatDate: formatDate

		})
	} else {

		let messages = await db.all(`SELECT messages.*, users.username AS senderUsername, users.permissionLevel AS senderPermissionLevel FROM messages LEFT JOIN users ON sender=users.id WHERE (receiver = ${user.id} OR receiver="ALL" OR sender = ${user.id}) AND (messages.id=? OR replyTo=?)`, scope, scope);
		
		// If message they tried to view doesn't exist
		if(messages.length == 0) {
			
			res.redirect("/messages"); 
			return; 

		}

		messages.forEach(message => {
			db.run(`INSERT INTO readReceipts (messageId, userId) 
			SELECT ?, ? WHERE NOT EXISTS 
			(SELECT * FROM readReceipts WHERE messageId=? AND userId=?)`, 
			message.id, user.id, message.id, user.id)
		})
		
		let unread = await getUnreadMessagesCount(user.id)

		res.render('thread', {

			user: user,
			unread: unread,
			messages: messages,
			formatDate: formatDate
			
		})

	}

})

app.get('/thread', checkAuthenticated, async (req, res) => {

	var user = null;
	let unread = await getUnreadMessagesCount(user.id)

	if (req.session.passport) {

		if (req.session.passport.user) user = await findUserById(req.session.passport.user)

	}

	if (user != null) updateLastSeen(user.id)

	res.render('register', {
		user: user,
		unread: unread,
		error: req.query.error
	})

})

app.get('/verify', async (req, res) => {

	var user = null;

	if (req.session.passport) {

		if (req.session.passport.user) user = await findUserById(req.session.passport.user)

	}

	let unread = 0;

	if (user != null) {
		updateLastSeen(user.id)
		unread = await getUnreadMessagesCount(user.id)
	}

	let code = req.query.code;
	if(code == null) res.redirect("/")
	let userWithCode = await db.get(`SELECT * FROM users WHERE verifyCode = ?`, code)

	if(userWithCode) {
		db.run(`UPDATE users SET isVerified = 1 WHERE verifyCode = "${code}"`)
	} else {
		res.render('/unverified');
		return;
	}

	res.render('verified', {
		user: user,
		unread: unread
	})

})

app.get('/contact', async (req, res) => {

	var user = null;

	if (req.session.passport) {

		if (req.session.passport.user) user = await findUserById(req.session.passport.user)

	}
	if(user == null) {
		res.redirect('/');
		return;
	}
	let unread = 0;

	if (user != null) {
		updateLastSeen(user.id)
		unread = await getUnreadMessagesCount(user.id)
	}

	if(req.query.completedform != null) {
		res.render('completedform', {
			user: user,
			unread: unread
		})
		return;
	}

	res.render('contact', {
		user: user,
		unread: unread,
		error: req.query.error // If form is not complete properly
	})

})





app.post('/contact', checkAuthenticated, async (req, res) => {

	var user = null;

	if (req.session.passport) {

		if (req.session.passport.user) user = await findUserById(req.session.passport.user)

	}

	if (user != null) updateLastSeen(user.id)

	// Insert message into database with myself as the receiver
	try {

		db.run(`INSERT INTO messages (sender, receiver, subject, body, sentTime) VALUES (?, ?, ?, ?, ?)`, [user.id, 1, req.body.subject, req.body.body, Date.now()])
		res.redirect('/contact?completedform=1')

	} catch (e) {

		res.redirect('/contact?error=1')
		console.log(e)

	}

})

app.post('/reply', checkAuthenticated, async (req, res) => {

	var user = null;

	if (req.session.passport) {

		if (req.session.passport.user) user = await findUserById(req.session.passport.user)

	}

	if (user != null) updateLastSeen(user.id)

	let originalMessage = req.body.messageId;
	let receiver = req.body.receiver;
	if(receiver == user.id) receiver = req.body.sender;
	let subject = req.body.subject
	let reply = req.body.body;

	// Insert message as a reply
	try {

		db.run(`INSERT INTO messages (sender, receiver, subject, body, sentTime, replyTo) VALUES (?, ?, ?, ?, ?, ?)`, user.id, receiver, subject, reply, Date.now(), originalMessage)
		res.redirect('/messages?message=' + originalMessage)

	} catch (e) {

		res.redirect('/messages?message=' + originalMessage)
		console.log(e)

	}

})

app.post('/sendverify', checkAuthenticated, async (req, res) => {

	var user = null;

	if (req.session.passport) {

		if (req.session.passport.user) user = await findUserById(req.session.passport.user)

	}

	if (user != null) updateLastSeen(user.id)

	sendActivationLink(user.email, user.verifyCode)

	res.redirect("/")

})

app.post('/labnew', checkAuthenticated, async (req, res) => {

	var user = null;

	if (req.session.passport) {

		if (req.session.passport.user) user = await findUserById(req.session.passport.user)

	}

	if (user != null) updateLastSeen(user.id)

	let existing = await db.get(`SELECT * FROM openings WHERE userId = ${user.id} AND name LIKE ?`, req.body.name)
	if(existing) {
		res.redirect("/labnew?error=1")
		return;
	} else {
		let nextIdSQL = await db.get(`SELECT seq FROM sqlite_sequence WHERE name="openings";`)
		let nextId = nextIdSQL.seq + 1
		db.run(`INSERT INTO openings (id, name, shared, userId, active) VALUES (?, ?, ?, ?, ?)`, [nextId, req.body.name, 0, user.id, 1])
		res.redirect("/lab?opening=" + nextId)

	}


})

app.post('/register', checkNotAuthenticated, async (req, res) => {
	/*
	ERROR CODES
		1
            Email taken   
        2
            Username taken
        3
            Email invalid
        4
            Username contains invalid characters
        5
            Password must be 8 characters minimum
        6
            Password contains invalid characters
		7
			Username too long
		8
			Unexpected error
	*/

	// Regex string to check if email is valid
	var regexEmail = /(?:(?:\r)?[ \t])*(?:(?:(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*))*@(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*|(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*)*\<(?:(?:\r)?[ \t])*(?:@(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*(?:,@(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*)*:(?:(?:\r)?[ \t])*)?(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*))*@(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*\>(?:(?:\r)?[ \t])*)|(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*)*:(?:(?:\r)?[ \t])*(?:(?:(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*))*@(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*|(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*)*\<(?:(?:\r)?[ \t])*(?:@(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*(?:,@(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*)*:(?:(?:\r)?[ \t])*)?(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*))*@(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*\>(?:(?:\r)?[ \t])*)(?:,\s*(?:(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*))*@(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*|(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*)*\<(?:(?:\r)?[ \t])*(?:@(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*(?:,@(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*)*:(?:(?:\r)?[ \t])*)?(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r)?[ \t]))*"(?:(?:\r)?[ \t])*))*@(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*)(?:\.(?:(?:\r)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r)?[ \t])*))*\>(?:(?:\r)?[ \t])*))*)?;\s*)/

	// Test the regex against the email
	if (!(regexEmail.test(req.body.email))) {

		res.redirect('/register?error=3')
		return;

	}

	// Check that username only contains letters and numbers
	if (!(/^[A-Za-z0-9]*$/.test(req.body.username))) {

		res.redirect('/register?error=4')
		return;

	}

	// Search to check username isn't already used
	let resultUsername = await db.get(`SELECT * FROM users WHERE username = ?`, [req.body.username])

	if (resultUsername != null) {

		res.redirect('/register?error=2')
		return;

	}

	// Search to check email isn't already used
	let resultEmail = await db.get(`SELECT * FROM users WHERE email = ?`, [req.body.email])

	if (resultEmail != null) {

		res.redirect('/register?error=1')
		return;

	}

	// Check password is atleast 8 characters
	if (req.body.password.length < 8) {

		res.redirect('/register?error=5')
		return;

	}

	// Check username isn't longer than 20 characters
	if (req.body.username.length > 20) {

		res.redirect('/register?error=7')
		return;

	}

	// Use bcrypt to hash password, then insert user into database
	try {

		const hashedPassword = await bcrypt.hash(req.body.password, 10)
		const randomCode = crypto.randomBytes(20).toString('hex');

		db.run(`INSERT INTO users (username, password, email, permissionLevel, joinedAt, lastSeen, isVerified, verifyCode) VALUES (?, ?, ?, 1, ?, ?, ?, ?)`, req.body.username, hashedPassword, req.body.email, Date.now(), Date.now(), 0, randomCode)
		sendActivationLink(req.body.email, randomCode)
		res.redirect('/login');
		return;

	} catch (e) {

		res.redirect('/register?error=8')
		console.log(e)

	}

})

// The delete route is used to logout (delete session essentially!)
app.post('/logout', (req, res) => {

	req.logOut(function (err) {

		if (err) {

			return next(err)

		}

		res.redirect('/')

	})

})

// The login post uses the passport authenticate rather than a standard setup
app.post('/login', checkNotAuthenticated, passport.authenticate('local', {

	successRedirect: "/",
	failureRedirect: "/login",
	failureFlash: true

}))

// This function can be passed for routing to only allow logged in users to access the page
async function checkAuthenticated(req, res, next) {

	if (req.session.passport) {
		var user = await findUserById(req.session.passport.user)
		if (user) {
			if(user.isVerified == 0) {
				res.redirect('/unverified')
				return;
			}
			return next()
		}

	}

	res.redirect('/login')

}

// This function can be passed for routing to only allow not logged in users to access the page
function checkNotAuthenticated(req, res, next) {

	if (req.isAuthenticated()) {

		return res.redirect('/');

	}

	next();

}

// Get number of unread messages
async function getUnreadMessagesCount(userId) {

	let result = await db.all(`SELECT * FROM messages AS m WHERE id NOT IN (SELECT messageId FROM readReceipts AS rr) AND (m.receiver = ${userId} OR m.receiver = "ALL")`);	
	return result.length;

}

// Format a epoch time int to dd/mm/yyyy hh:mm
function formatDate(date) {

	var hours = date.getHours();
	var minutes = date.getMinutes();

	var ampm = hours >= 12 ? 'pm' : 'am';

	hours = hours % 12;
	hours = hours ? hours : 12; // the hour '0' should be '12'

	minutes = minutes < 10 ? '0' + minutes : minutes;

	var strTime = hours + ':' + minutes + ' ' + ampm;

	return date.getDate() + "/" + (date.getMonth() + 1) + "/" + date.getFullYear() + "  " + strTime;

}

// Express to listen on the specified port
app.listen(port, () => console.log(`Server started on port ${port}.`))