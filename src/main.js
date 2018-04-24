var watchman = require("fb-watchman");
var client = new watchman.Client();
var subscriptionName = "VIRUSTOTALSUBSCRIPTION";
require("dotenv").config();
var apiKey = process.env.VIRUSTOTALAPIKEY;
if (!apiKey) {
	throw new Error("Api key not set in environment variable VIRUSTOTALAPIKEY.");
}
var dir_of_interest = process.env.DIRECTORYOFINTEREST;
if (!dir_of_interest) {
	throw new Error(
		"Directory not set in environment variable DIRECTORYOFINTEREST."
	);
}
var timeout = Number(process.env.VIRUSTOTALTIMEOUT);
if (!timeout) {
	throw new Error("Timeout not set in environment variable VIRUSTOTALTIMEOUT.");
}
if (!timeout < 1) {
	console.warn("Timeout should be at least 1 second.");
}
var http = require("https");
var fs = require("fs");

client.capabilityCheck({
		optional: [],
		required: ["relative_root"]
	},
	(error, resp) => {
		if (error) {
			console.log(error);
			client.end();
			return;
		}

		client.command(["watch-project", dir_of_interest], (error, resp) => {
			if (error) {
				console.error("Error initiating watch:", error);
				return;
			}
			if ("warning" in resp) {
				console.log("warning: ", resp.warning);
			}
			console.log(
				"watch established on ",
				resp.watch,
				" relative_path",
				resp.relative_path
			);
			make_time_constrained_subscription(
				client,
				resp.watch,
				resp.relative_path
			);
		});
	}
);


function make_time_constrained_subscription(client, watch, relative_path) {
	client.command(["clock", watch], (error, resp) => {
		if (error) {
			console.error("Failed to query clock:", error);
			return;
		}

		sub = {
			expression: ["allof", ["match", "*.*"]],
			fields: ["exists", "name", "type", "new"],
			since: resp.clock
		};

		if (relative_path) {
			sub.relative_root = relative_path;
		}

		client.command(
			["subscribe", watch, subscriptionName, sub],
			(error, resp) => {
				if (error) {
					console.error("failed to subscribe: ", error);
					return;
				}
				console.log("subscription " + resp.subscribe + " established");
			}
		);

		client.on("subscription", resp => {
			if (resp.subscription !== subscriptionName) return;

			resp.files.forEach(file => {
				if (file.exists && file.new) {
					var crypto = require("crypto");
					var algorithm = "sha256";
					var shasum = crypto.createHash(algorithm);

					const fullname = dir_of_interest + "/" + file.name;
					var stream = fs.ReadStream(fullname);
					stream.on("data", data => {
						shasum.update(data);
					});

					stream.on("end", () => {
						var hash = shasum.digest("hex");
						scan(hash, fullname);
					});
				}
			});
		});
	});
}

function scan(hash, fileName) {
	var url =
		"https://www.virustotal.com/vtapi/v2/file/report?apikey=" +
		apiKey +
		"&resource=" +
		hash;
	http.get(url, response => {
		response.setEncoding("utf8");
		let body = "";
		response.on("data", data => {
			checkStatus(response);
			body += data;
		});
		response.on("end", () => {
			checkStatus(response);
			body = JSON.parse(body);
			checkResponseCode(hash, body, fileName);
		});
	});
}

function checkResponseCode(hash, body, fileName) {
	switch (body.response_code) {
		case 1:
			console.log("Item present");
			if (body.positives > 0) {
				console.log("VirusTotal found something");
			}
			console.log("See " + body.permalink + " for more information.");
			break;
		case -2:
			console.log("Item still queued");
			setTimeout(() => scan(hash, fileName), timeout);
			break;
		case 0:
			console.log("Item not present");
			scanFirstTime(hash, fileName);
			setTimeout(() => scan(hash, fileName), timeout);
			break;
		default:
			console.error("Something unexpected happened.");
	}
}

function scanFirstTime(hash, fileName) {
	var fileStream = fs.createReadStream(fileName);
	var url = "https://www.virustotal.com/vtapi/v2/file/scan";
	var request = require("request");
	var formData = {
		apikey: apiKey,
		file: fs.createReadStream(fileName)
	};
	request.post({
			url: url,
			formData: formData
		},
		function optionalCallback(err, response, body) {
			if (err) {
				return console.error("upload failed:", err);
			}
			body = JSON.parse(body);
			console.log("Upload successful!  Server responded with");
			checkStatus(response);
			checkResponseCode(hash, body, fileName);
		}
	);
}

function checkStatus(response) {
	if (response.statusCode === 204) {
		console.log(
			"Request rate limit exceeded. You are making more requests than allowed."
		);
	}
	if (response.statusCode === 400) {
		console.log(
			"Bad request.Your request was somehow incorrect.This can be caused by missing arguments or arguments with wrong values."
		);
	}
	if (response.statusCode === 403) {
		console.log(
			"Forbidden.You don 't have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges."
		);
	}
}

function onExit(type) {
	client.command(["watch-del", dir_of_interest]);
	client.command(['unsubscribe', dir_of_interest, subscriptionName]);
	console.log(type);
	process.exit();
}

process.on('exit', () => onExit('exit'));
process.on('uncaughtException', () => onExit('uncaughtException'));
process.on('SIGINT', () => onExit('SIGINT'));
process.on('SIGUSR1', () => onExit('SIGUSR1'));
process.on('SIGUSR2', () => onExit('SIGUSR2'));