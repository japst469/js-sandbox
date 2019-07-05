const { app, BrowserWindow } = require('electron');
const path = require('path');
const url = require('url');
const fs = require('fs');
const crypto = require("crypto"), algorithm = 'aes-256-ctr', password = 'WhorrySheetsB@tm@n';
const artoo = require('artoo-js');
const cheerio = require('cheerio');
const hash = require('hash-files');
const jquery = require('jquery');
const wget = require('node-wget');
const http = require('http');
const https = require('https');
const Nightmare = require('nightmare');
const nightmare = Nightmare({
	electronPath: require('./node_modules/electron'),
	show: false,
});
const names = require('random-name');
const mysql = require('mysql');



const util = {};
util.getFileChecksum = function (hashName, path) {
	return new Promise((resolve, reject) => {
		let hash = crypto.createHash(hashName);
		let stream = fs.createReadStream(path);
		stream.on('error', err => reject(err));
		stream.on('data', chunk => hash.update(chunk));
		stream.on('end', () => resolve(hash.digest('hex')));
	});
}

util.copyFileTo = function(file, path) {
	fs.createReadStream(file).pipe(fs.createWriteStream(path + file));
}

util.encrypt = function(text) {
	let cipher = crypto.createCipher(algorithm, password)
	let encrypted = cipher.update(text.toString(), 'utf8', 'hex')
	encrypted += cipher.final('hex');
	return encrypted;
}

util.decrypt = function(text) {
	let decipher = crypto.createDecipher(algorithm, password)
	let dec = decipher.update(text.toString(), 'hex', 'utf8')
	dec += decipher.final('utf8');
	return dec;
}

const secrets = JSON.parse( util.decrypt(fs.readFileSync('970f1d694be21ccf39cd58b6d9d7c788') ) );

util.us_states = [
	{ "name": "Alabama", "abbrev": "AL", "fips": 01 },
	{ "name": "Alaska", "abbrev": "AK", "fips": 02 },
	{ "name": "Arizona", "abbrev": "AZ", "fips": 04 },
	{ "name": "Arkansas", "abbrev": "AR", "fips": 05 },
	{ "name": "California", "abbrev": "CA", "fips": 06 },
	{ "name": "Colorado", "abbrev": "CO", "fips": 08 },
	{ "name": "Connecticut", "abbrev": "CT", "fips": 09 },
	{ "name": "Delaware", "abbrev": "DE", "fips": 10 },
	{ "name": "District of Columbia", "abbrev": "DC", "fips": 11 },
	{ "name": "Florida", "abbrev": "FL", "fips": 12 },
	{ "name": "Georgia", "abbrev": "GA", "fips": 13 },
	{ "name": "Hawaii", "abbrev": "HI", "fips": 15 },
	{ "name": "Idaho", "abbrev": "ID", "fips": 16 },
	{ "name": "Illinois", "abbrev": "IL", "fips": 17 },
	{ "name": "Indiana", "abbrev": "IN", "fips": 18 },
	{ "name": "Iowa", "abbrev": "IA", "fips": 19 },
	{ "name": "Kansas", "abbrev": "KS", "fips": 20 },
	{ "name": "Kentucky", "abbrev": "KY", "fips": 21 },
	{ "name": "Louisiana", "abbrev": "LA", "fips": 22 },
	{ "name": "Maine", "abbrev": "ME", "fips": 23 },
	{ "name": "Maryland", "abbrev": "MD", "fips": 24 },
	{ "name": "Massachusetts", "abbrev": "MA", "fips": 25 },
	{ "name": "Michigan", "abbrev": "MI", "fips": 26 },
	{ "name": "Minnesota", "abbrev": "MN", "fips": 27 },
	{ "name": "Mississippi", "abbrev": "MS", "fips": 28 },
	{ "name": "Missouri", "abbrev": "MO", "fips": 29 },
	{ "name": "Montana", "abbrev": "MT", "fips": 30 },
	{ "name": "Nebraska", "abbrev": "NE", "fips": 31 },
	{ "name": "Nevada", "abbrev": "NV", "fips": 32 },
	{ "name": "New Hampshire", "abbrev": "NH", "fips": 33 },
	{ "name": "New Jersey", "abbrev": "NJ", "fips": 34 },
	{ "name": "New Mexico", "abbrev": "NM", "fips": 35 },
	{ "name": "New York", "abbrev": "NY", "fips": 36 },
	{ "name": "North Carolina", "abbrev": "NC", "fips": 37 },
	{ "name": "North Dakota", "abbrev": "ND", "fips": 38 },
	{ "name": "Ohio", "abbrev": "OH", "fips": 39 },
	{ "name": "Oklahoma", "abbrev": "OK", "fips": 40 },
	{ "name": "Oregon", "abbrev": "OR", "fips": 41 },
	{ "name": "Pennsylvania", "abbrev": "PA", "fips": 42 },
	{ "name": "Rhode Island", "abbrev": "RI", "fips": 44 },
	{ "name": "South Carolina", "abbrev": "SC", "fips": 45 },
	{ "name": "South Dakota", "abbrev": "SD", "fips": 46 },
	{ "name": "Tennessee", "abbrev": "TN", "fips": 47 },
	{ "name": "Texas", "abbrev": "TX", "fips": 48 },
	{ "name": "Utah", "abbrev": "UT", "fips": 49 },
	{ "name": "Vermont", "abbrev": "VT", "fips": 50 },
	{ "name": "Virginia", "abbrev": "VA", "fips": 51 },
	{ "name": "Washington", "abbrev": "WA", "fips": 53 },
	{ "name": "West Virginia", "abbrev": "WV", "fips": 54 },
	{ "name": "Wisconsin", "abbrev": "WI", "fips": 55 },
	{ "name": "Wyoming", "abbrev": "WY", "fips": 56 }
];
util.convert = { bin2dec: s => parseInt(s, 2).toString(10), bin2hex: s => parseInt(s, 2).toString(16), dec2bin: s => parseInt(s, 10).toString(2), dec2hex: s => parseInt(s, 10).toString(16), hex2bin: s => parseInt(s, 16).toString(2), hex2dec: s => parseInt(s, 16).toString(10) };
util.alphanumerals = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
util.getMedian = function(a) { var s = a.sort((a, b) => { return a - b; }); i = Math.floor((s.length - 1) / 2); return s[i] + (s[i + 1] - s[i]) / 2; };

util.hash = function (string, algorithm) {
	let hash = crypto.createHash(algorithm).update(string).digest('hex');
	return hash;
}

util.arrayUniqueify = function(array) {
	var seen = {};
	var out = [];
	var len = array.length;
	var j = 0;
	for (var i = 0; i < len; i++) {
		array[i].hash = util.hash(JSON.stringify(array[i]), 'sha1');
		var item = array[i].hash;
		if (seen[item] !== 1) {
			seen[item] = 1;
			out[j++] = array[i];
		}
	}
	return out;
}
util.arrayMerge = function(arr1, arr2) {
	function arrayUnique(arr) {
		var a = arr.concat();
		for (var i = 0; i < a.length; ++i) {
			for (var j = i + 1; j < a.length; ++j) {
				if (Object.prototype.toString.call(a[i]) === "[object Object]") {
					// we need to check deeper in the object for equality...
					// get a hash of the object, that should give us a pretty good uniqueness for that object. if there is hash collision then poof this wont work.

				} else if (a[i] === a[j])
					a.splice(j--, 1);
			}
		}

		return a;
	}
	                                       
	var result = arrayUnique(arr1.concat(arr2));
	//var txt = "";
	//result.forEach( (e,i,a)=>{ txt+=(e + "\n"); } );
	return result;
}
util.arrayRemove = function(array, element) {
	if (Object.prototype.toString.call(array) === '[object Array]') {
		let index = array.indexOf(element);
		if (index !== -1) {
			array.splice(index, 1);
			return array;
		} else {
			// no such element
			return array;
		}
	}
}
util.repeatChar = function (char, length) {
	let a = "";
	for (var i = 0; i < length; i++)
		a += char;
	return a;
}
//The max and min are inclusive
util.getRandomNumber = function (min, max) {
	min = Math.ceil(min);
	max = Math.floor(max);
	return Math.floor(Math.random() * (max - min + 1)) + min;
}
util.getRandomAlphaNumeral = function () {
	return this.alphanumerals[util.getRandomNumber(0, 61)];
}

util.getRandomPassword = function (length) {
	let pass = "";
	let exclude = [92, 59];
	for (var i = 0; i < length; i++) {
		let r = util.getRandomNumber(33, 126);
		while (r === 92 || r === 59) { r = util.getRandomNumber(32, 126) };
		pass += String.fromCharCode(r);
	}
	return pass;
};
util.getRandomEmail = function () {
	const mails = ["gmail.com", "yahoo.com", "msn.com", "mail.org", "mail.s.com"];
	let email = mails[util.getRandomNumber(0, mails.length - 1)];
	return names.first().toLowerCase() + "." + names.last().toLowerCase() + "@" + email;
}
util.getRandomAddress = function () {
	
}

util.fetch = function (url, callback) {
	https.get(url, res => {
		res.setEncoding("utf8");
		let body = "";
		res.on('data', data => {
			body += data;
		});
		res.on('end', () => {
			callback(null, body);
		});
	});
};



util.stuff = function (error, data) {
	console.log(error, data);
	let filename = opts.dest;
	var fd = fs.createReadStream(filename);

	var hashlist = ['md5', 'sha1', 'sha256'];
	var hashes = [];
	var results = [];
	var matched = false;

	hashlist.forEach((e, i, a) => {
		hashes[i] = crypto.createHash(e);
		hashes[i].setEncoding('hex');
	});
	console.log(filename);

	fd.on('end', function () {
		hashes.forEach((e, i, a) => {
			hashes[i].end();
			results[i] = hashes[i].read();
			let str = hashlist[i] + ": " + results[i];
			if (checksum == results[i]) {
				str += " <== SUCCESSFUL MATCH";
				matched = true;
			}

			console.log(str);
		});
		if (!matched) { console.log("NO MATCHES FOUND."); }
		callback(null, filename);
	});

	// pipe the filestream to each hash in the list.
	hashes.forEach((e, i, a) => {
		fd.pipe(e)
	});

};

util.download = function (url, callback) {
	//wget({url: url, dest: destination_folder_or_filename}, callback);
	let opts = {
		url: url,
		dest: "./downloads/" + url
	}
	let response = wget(opts, console.log( err, data ));

	console.log(response);
};

var dbConn = mysql.createConnection({
	host: '127.0.0.1',
	user: secrets['mysql-user'],
	password: secrets['mysql-pass'],
	database: secrets['mysql-db']
});
dbConn.connect(function (err) {
	if (err) {
		console.error('error connecting: ' + err.stack);
		return;
	}

	console.log('connected as id ' + dbConn.threadId);
});




app.on('ready', createWindow);

app.on('window-all-closed', () => {
	if (process.platform !== 'darwin') {
		dbConn.end();
		app.quit();
	}
});

let win = {};
function createWindow() {
	win = new BrowserWindow({
		width: 1920,
		height: 1080,
		icon: path.join(__dirname, '/icon.png')
	});

	win.webContents.openDevTools();

	win.fs = fs;
	win.crypto = crypto;
	win.artoo = artoo;
	win.wget = wget;
	win.cheerio = cheerio;
	win.nightmare = nightmare;
	win.names = names;
	win.mysql = mysql;
	win.dbConn = dbConn;
	win.wget = wget;
	win.util = util;

	win.loadURL(`file://${__dirname}/index.html`);
	win.on('closed', () => { win = null; });

}
