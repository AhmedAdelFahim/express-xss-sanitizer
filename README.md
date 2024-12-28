# Express XSS Sanitizer
Express 4.x and 5.x middleware which sanitizes user input data (in req.body, req.query, req.headers and req.params) to prevent Cross Site Scripting (XSS) attack.

[![Build Status](https://img.shields.io/github/forks/AhmedAdelFahim/express-xss-sanitizer.svg?style=for-the-badge)](https://github.com/AhmedAdelFahim/express-xss-sanitizer)
[![Build Status](https://img.shields.io/github/stars/AhmedAdelFahim/express-xss-sanitizer.svg?style=for-the-badge)](https://github.com/AhmedAdelFahim/express-xss-sanitizer)
[![Latest Stable Version](https://img.shields.io/npm/v/express-xss-sanitizer.svg?style=for-the-badge)](https://www.npmjs.com/package/express-xss-sanitizer)
[![License](https://img.shields.io/npm/l/express-xss-sanitizer.svg?style=for-the-badge)](https://www.npmjs.com/package/express-xss-sanitizer)
[![NPM Downloads](https://img.shields.io/npm/dt/express-xss-sanitizer.svg?style=for-the-badge)](https://www.npmjs.com/package/express-xss-sanitizer)
[![NPM Downloads](https://img.shields.io/npm/dm/express-xss-sanitizer.svg?style=for-the-badge)](https://www.npmjs.com/package/express-xss-sanitizer)
## Installation
```bash
$ npm install express-xss-sanitizer
```
## Usage
Add as a piece of express middleware, before defining your routes.
```javascript
const express = require('express');
const bodyParser = require('body-parser');
const { xss } = require('express-xss-sanitizer');

const app = express();

app.use(bodyParser.json({limit:'1kb'}));
app.use(bodyParser.urlencoded({extended: true, limit:'1kb'}));
app.use(xss());
```
You can add options to specify allowed keys or allowed attributes to be skipped at sanitization
```javascript
const options = {
   allowedKeys: ['name'],
   allowedAttributes: {
         input: ['value'],
   },
}

app.use(xss(options));
```
You can add options to specify allowed tags to sanitize it and remove other tags
```javascript
const options = {
   allowedTags: ['h1']
}

app.use(xss(options));
```
Add as a piece of express middleware, before single route.
```javascript
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
__Note:__ if you adding xxs() as application level middleware, the xxs() will sanitize req.body, req.headers and req.query only and for req.params you must add xxs() as route level middleware like below example.

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const { xss } = require('express-xss-sanitizer');

const app = express();

app.use(bodyParser.json({limit:'1kb'}));
app.use(bodyParser.urlencoded({extended: true, limit:'1kb'}));
app.post("/params/:val", xss(), function (req, res) {
      // your code
});

```
You also can sanitize your data (object, array, string,etc) on the fly.
```javascript
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
