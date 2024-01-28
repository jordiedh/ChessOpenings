import dotenv from 'dotenv'
if (process.env.NODE_ENV !== "production") {
	dotenv.config()
}

// Imports
import express from 'express';
import path from 'path';
import bcrypt from 'bcrypt';
import {
	fileURLToPath
} from 'url';
import bodyParser from 'body-parser';
import sqlite3 from 'sqlite3';
import {
	open
} from 'sqlite';
import {
	Chess
} from 'chess.js';
import passport from 'passport';
import redis from 'redis';
import RedisStore from 'connect-redis';
import session from 'express-session';
import flash from 'express-flash';
import methodOverride from 'method-override';
import cookieParser from 'cookie-parser';
var db;
import initializePassport from './passport-config.js'
initializePassport(passport, email => findUserByEmail(email), id => findUserById(id))

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
		lastSeen: result.lastSeen
	}


}

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
		lastSeen: result.lastSeen
	}

}

const redisClient = redis.createClient({
	host: '127.0.0.1',
		port: 6379,
});
redisClient.connect().catch(console.error)
redisClient.on('error', function (err) {
	console.log('Could not establish a connection with redis. ' + err);
});
redisClient.on('connect', function (err) {
	console.log('Connected to redis successfully');
});
const app = express();
let port = 8000;

(async () => {
	db = await open({
		filename: "./db.db",
		driver: sqlite3.Database
	})
})()

const __filename = fileURLToPath(
	import.meta.url); // Get the directory URL

app.set('view engine', 'ejs'); // Set webpages to run from EJS
app.use(express.static(path.dirname(__filename) + '/public')); // Set the public view folder to /public (to get images, css, etc.)
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(flash())
app.use(passport.initialize())
app.use(methodOverride('_method'))
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


init();

// initialise function
function init() {

}

function updateLastSeen(userId) {
	try {
		db.run("UPDATE users SET lastSeen = ? WHERE id = ?", [Date.now(), userId]);
		return true;
	} catch(e) {
		console.error(e)
	}
}

app.get('/', async (req, res) => {
	var user = null;
	if(req.session.passport) {
		if(req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if(user != null) updateLastSeen(user.id)

	res.render('home', {
		user: user
	})

})

app.get('/preferences', checkAuthenticated, async (req, res) => {
	var user = null;
	if(req.session.passport) {
		if(req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if(user != null) updateLastSeen(user.id)

	res.render('preferences', {
		user: user
	})

})
function formatDate(date) {
	var hours = date.getHours();
	var minutes = date.getMinutes();
	var ampm = hours >= 12 ? 'pm' : 'am';
	hours = hours % 12;
	hours = hours ? hours : 12; // the hour '0' should be '12'
	minutes = minutes < 10 ? '0'+minutes : minutes;
	var strTime = hours + ':' + minutes + ' ' + ampm;
	return date.getDate() + "/" + (date.getMonth()+1) + "/" + date.getFullYear() + "  " + strTime;
  }

app.get('/users', checkAuthenticated, async (req, res) => {
	var user = null;
	if(req.session.passport) {
		if(req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if(user != null) updateLastSeen(user.id)

	if(user.permissionLevel < 100) {
		res.redirect("/")
		return;
	}

	let users = await db.all("SELECT * FROM users");

	res.render('users', {
		user: user,
		users: users,
		formatDate: formatDate
	})

})

app.get('/account', checkAuthenticated, async (req, res) => {
	var user = null;
	if(req.session.passport) {
		if(req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if(user != null) updateLastSeen(user.id)

	res.render('account', {
		user: user
	})

})

app.get('/lab', checkAuthenticated, async (req, res) => {
	var user = null;
	if(req.session.passport) {
		if(req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if(user != null) updateLastSeen(user.id)
	let selectedOpening = req.query.opening;
	if(selectedOpening == null) {
		var userOpenings = null;
		if(user.permissionLevel < 100) userOpenings = await db.all("SELECT * FROM openings WHERE active = 1 AND userId = " + user.id)
		else userOpenings = await db.all("SELECT * FROM openings WHERE active = 1 AND (userId = " + user.id + " OR shared = 1)")

		res.render('lab', {
			user: user,
			userOpenings: userOpenings
		})
	} else {

		/*

		1
			Opening does not exist
		2
			User cannot access this opening
		3
			Opening has no moves (or does not exist)

		*/
		var opening = null;
		opening = await db.get("SELECT * FROM openings WHERE id = ?", [selectedOpening])
		if(opening == null) {
			res.redirect('/openingselection?error=1');
			return;
		}
		if((opening.shared == 1 && user.permissionLevel < 100) || opening.userId != user.id) {
			res.redirect('/openingselection?error=2');
			return;
		}

		res.render('labedit', {
			user: user,
			userOpenings: userOpenings
		})
	}
})

app.get('/practice', checkAuthenticated, async (req, res) => {
	var user = null;
	if(req.session.passport) {
		if(req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if(user != null) updateLastSeen(user.id)
	var openingId = req.query.opening;
	if(openingId == null) {
		res.redirect("/openingselection?error=3")
		return;
	}
	let opening = await db.get(`SELECT * FROM openings WHERE id=?`, [openingId]).catch(err => {console.error(err)})
	if(opening == null) {
		res.redirect("/openingselection?error=3")
		return;
	}
	let moves = await db.all(`SELECT * FROM moves WHERE openingId=?`, [openingId])
	if(moves.length == 0) {
		res.redirect("/openingselection?error=3")
		return;
	}
	res.render('practice', {
		Chess: Chess,
		user: user,
		opening: opening,
		moves: moves
	})

})

app.get('/openingselection', checkAuthenticated, async (req, res) => {
	var user = null;
	if(req.session.passport) {
		if(req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if(user != null) updateLastSeen(user.id)

	let siteOpenings = await db.all("SELECT * FROM openings WHERE active = 1 AND shared = 1")
	let userOpenings = await db.all("SELECT * FROM openings WHERE active = 1 AND userId = " + user.id)
	
	res.render('openingselection', {
		user: user,
		siteOpenings: siteOpenings,
		userOpenings: userOpenings
	})

})

app.get('/login', checkNotAuthenticated, async (req, res) => {
	var user = null;
	if(req.session.passport) {
		if(req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if(user != null) updateLastSeen(user.id)
	res.render('login', {
		user: user
	})

})

app.get('/register', checkNotAuthenticated, async (req, res) => {
	var user = null;
	if(req.session.passport) {
		if(req.session.passport.user) user = await findUserById(req.session.passport.user)
	}
	if(user != null) updateLastSeen(user.id)
	res.render('register', {
		user: user,
		error: req.query.error
	})

})

app.post('/register', checkNotAuthenticated, async (req, res) => {
	/*
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
	*/

	var regexEmail = /(?:(?:\r\n)?[ \t])*(?:(?:(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*))*@(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*|(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*)*\<(?:(?:\r\n)?[ \t])*(?:@(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*(?:,@(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*)*:(?:(?:\r\n)?[ \t])*)?(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*))*@(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*\>(?:(?:\r\n)?[ \t])*)|(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*)*:(?:(?:\r\n)?[ \t])*(?:(?:(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*))*@(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*|(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*)*\<(?:(?:\r\n)?[ \t])*(?:@(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*(?:,@(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*)*:(?:(?:\r\n)?[ \t])*)?(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*))*@(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*\>(?:(?:\r\n)?[ \t])*)(?:,\s*(?:(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*))*@(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*|(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*)*\<(?:(?:\r\n)?[ \t])*(?:@(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*(?:,@(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*)*:(?:(?:\r\n)?[ \t])*)?(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|"(?:[^\"\r\\]|\\.|(?:(?:\r\n)?[ \t]))*"(?:(?:\r\n)?[ \t])*))*@(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*)(?:\.(?:(?:\r\n)?[ \t])*(?:[^()<>@,;:\\".\[\] \000-\031]+(?:(?:(?:\r\n)?[ \t])+|\Z|(?=[\["()<>@,;:\\".\[\]]))|\[([^\[\]\r\\]|\\.)*\](?:(?:\r\n)?[ \t])*))*\>(?:(?:\r\n)?[ \t])*))*)?;\s*)/

	if(!(regexEmail.test(req.body.email))) {
		res.redirect('/register?error=3')
		return;
	}


	if(!(/^[A-Za-z0-9]*$/.test(req.body.username))) {
		res.redirect('/register?error=4')
		return;
	}

	let resultUsername = await db.get(`SELECT * FROM users WHERE username = ?`, [req.body.username])
	if (resultUsername != null) {
		res.redirect('/register?error=2')
		return;
	}
	let resultEmail = await db.get(`SELECT * FROM users WHERE email = ?`, [req.body.email])
	if (resultEmail != null) {
		res.redirect('/register?error=1')
		return;
	}
	if(req.body.password.length < 8) {
		res.redirect('/register?error=5')
		return;
	}
	if(req.body.username.length > 20) {
		res.redirect('/register?error=7')
		return;
	}
	try {
		const hashedPassword = await bcrypt.hash(req.body.password, 10)
		db.run(`INSERT INTO users (username, password, email, permissionLevel, joinedAt, lastSeen) VALUES (?, ?, ?, 1, ?, ?)`, req.body.username, hashedPassword, req.body.email, Date.now(), Date.now())
		res.redirect('/login')
	} catch (e) {
		res.redirect('/register')
		console.log(e)
	}

})

app.delete('/logout', (req, res) => {
	req.logOut(function (err) {
		if (err) {
			return next(err)
		}
		res.redirect('/')
	})
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
	successRedirect: "/",
	failureRedirect: "/login",
	failureFlash: true
}))

function checkAuthenticated(req, res, next) {
	if (req.session.passport) {
		if(findUserById(req.session.passport.user)) return next()
	}

	res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		return res.redirect('/')
	}
	next()
}

app.listen(port, () => console.log(`Server started on port ${port}.`))