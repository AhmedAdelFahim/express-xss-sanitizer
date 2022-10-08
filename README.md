# Express XSS Sanitizer
Express 4.x middleware which sanitizes user input data (in req.body, req.query, req.headers and req.params) to prevent Cross Site Scripting (XSS) attack.

![GitHub](https://img.shields.io/github/license/ahmedadelfahim/express-xss-sanitizer) ![npm](https://img.shields.io/npm/v/express-xss-sanitizer) ![Snyk Vulnerabilities for npm package](https://img.shields.io/snyk/vulnerabilities/npm/express-xss-sanitizer) ![npm](https://img.shields.io/npm/dt/express-xss-sanitizer)
## Installation
```bash
$ npm install express-xss-sanitizer
```
## Usage
Add as a piece of express middleware, before defining your routes.
```
const express = require('express');
const bodyParser = require('body-parser');
const { xss } = require('express-xss-sanitizer');

const app = express();

app.use(bodyParser.json({limit:'1kb'}));
app.use(bodyParser.urlencoded({extended: true, limit:'1kb'}));
app.use(xss());
```
You can add options to specify allowed keys to be skipped at sanitization
```
const options = {
   allowedKeys: ['name']
}

app.use(xss(options));
```
You can add options to specify allowed tags to sanitize it and remove other tags
```
const options = {
   allowedTags: ['h1']
}

app.use(xss(options));
```
Add as a piece of express middleware, before single route.
```
const express = require('express');
const bodyParser = require('body-parser');
const { xss } = require('express-xss-sanitizer');

const app = express();

app.use(bodyParser.json({limit:'1kb'}));
app.use(bodyParser.urlencoded({extended: true, limit:'1kb'}));
app.post("/body", xss(), function (req, res) {
      // your code
});

app.post("/test", function (req, res) {
      // your code
});
```
You also can sanitize your data (object, array, string,etc) on the fly.
```
const { sanitize } = require('express-xss-sanitizer');

// ...
      data = sanitize(data)
// or
      data = sanitize(data, {allowedKeys: ['name']})
// ...
```
## For other frameworks
 * [koa-xss-sanitizer](https://www.npmjs.com/package/koa-xss-sanitizer)

## Tests
To run the test suite, first install the dependencies, then run `npm test`:
```bash
$ npm install
$ npm test
```
## Support
Feel free to open issues on [github](https://github.com/AhmedAdelFahim/express-xss-sanitizer.git).