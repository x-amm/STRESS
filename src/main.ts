// Require
const watchman = require("fb-watchman");
const fs = require("fs");
const crypt = require("crypto");
const request = require("request");

// Load environment variables
const dotenv = require("dotenv").config();
if (dotenv.error) {
  console.error(dotenv.error);
  process.exit();
}
const subscriptionName = "VIRUSTOTALSUBSCRIPTION";

// Check environment variables
const apiKey = process.env.VIRUSTOTALAPIKEY;
if (!apiKey) {
  throw new Error("Api key not set in environment variable VIRUSTOTALAPIKEY.");
}

const dir_of_interest = process.env.DIRECTORYOFINTEREST;
if (!dir_of_interest) {
  throw new Error(
    "Directory not set in environment variable DIRECTORYOFINTEREST."
  );
}

let timeout = Number(process.env.VIRUSTOTALTIMEOUT);
if (!timeout) {
  throw new Error("Timeout not set in environment variable VIRUSTOTALTIMEOUT.");
}
if (timeout < 1) {
  console.warn("Timeout should be at least 1 second.");
}
// convert to minutes
timeout = timeout * 60000;

// Create and use Watchman client
const client = new watchman.Client();

// Create cleanup hooks
function onExit(type: string) {
  client.command(["watch-del", dir_of_interest]);
  client.command(["unsubscribe", dir_of_interest, subscriptionName]);
  console.log(type);
  process.exit();
}

process.on("exit", () => onExit("exit"));
process.on("uncaughtException", () => onExit("uncaughtException"));
process.on("SIGINT", () => onExit("SIGINT"));
process.on("SIGUSR1", () => onExit("SIGUSR1"));
process.on("SIGUSR2", () => onExit("SIGUSR2"));

client.capabilityCheck(
  {
    optional: [],
    required: ["relative_root"]
  },
  (error: Error) => {
    if (error) {
      console.log(error);
      client.end();
      return;
    }

    client.command(
      ["watch-project", dir_of_interest],
      (error: Error, resp: any) => {
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
        makeTimeConstrainedSubscription(client, resp.watch, resp.relative_path);
      }
    );
  }
);

function makeTimeConstrainedSubscription(
  client: any,
  watch: any,
  relative_path: any
) {
  client.command(["clock", watch], (error: Error, resp: any) => {
    if (error) {
      console.error("Failed to query clock:", error);
      return;
    }

    const sub = {
      expression: ["allof", ["match", "*.*"]],
      fields: ["exists", "name", "type", "new"],
      since: resp.clock,
      relative_root: ""
    };

    if (relative_path) {
      sub.relative_root = relative_path;
    }

    client.command(
      ["subscribe", watch, subscriptionName, sub],
      (error: Error, resp: any) => {
        if (error) {
          console.error("failed to subscribe: ", error);
          return;
        }
        console.log("subscription " + resp.subscribe + " established");
      }
    );

    client.on("subscription", (resp: any) => {
      if (resp.subscription !== subscriptionName) return;

      resp.files.forEach((file: any) => {
        if (file.exists && file.new) {
          var algorithm = "sha256";
          var shasum = crypt.createHash(algorithm);

          const fullname = dir_of_interest + "/" + file.name;
          var stream = fs.ReadStream(fullname);
          stream.on("data", (data: any) => {
            shasum.update(data);
          });

          stream.on("end", () => {
            var hash = shasum.digest("hex");
            getReport(hash, fullname);
          });
        }
      });
    });
  });
}

// Check if report is existing
function getReport(hash: string, fileName: string) {
  const url =
    "https://www.virustotal.com/vtapi/v2/file/report?apikey=" +
    apiKey +
    "&resource=" +
    hash;
  request.get(url, (err: Error, response: any) => {
    if (err) {
      console.error(err);
    }
    checkStatus(response);
    const body = JSON.parse(response.body);
    waitForRateLimit(response, checkResponseCode, { hash, body, fileName });
  });
}

function checkResponseCode(options: {
  hash: string;
  body: any;
  fileName: string;
}) {
  let hash: string = options.hash;
  let body: any = options.body;
  let fileName: string = options.fileName;
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
      setTimeout(() => getReport(hash, fileName), timeout);
      break;
    case 0:
      console.log("Item not present");
      scanFirstTime(hash, fileName);
      setTimeout(() => getReport(hash, fileName), timeout);
      break;
    default:
      console.error("Something unexpected happened.");
  }
}

// Scan if file did not exist already
function scanFirstTime(hash: string, fileName: string) {
  const url = "https://www.virustotal.com/vtapi/v2/file/scan";
  const formData = {
    apikey: apiKey,
    file: fs.createReadStream(fileName)
  };
  request.post(
    {
      url: url,
      formData: formData
    },
    function optionalCallback(err: Error, response: any, body: string) {
      if (err) {
        return console.error("upload failed:", err);
      }
      body = JSON.parse(body);
      console.log("Upload successful!  Server responded with");

      checkStatus(response);
      waitForRateLimit(response, checkResponseCode, { hash, body, fileName });
    }
  );
}

function waitForRateLimit(response: any, callback: Function, options: object) {
  if (response.statusCode === 204) {
    setTimeout(() => callback(options), timeout);
  } else {
    callback(options);
  }
}

function checkStatus(response: any) {
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
