'use strict';

const sanitize = require('./lib/sanitize');

function middleware(options = {}) {
  return (req, res, next) => {
    ['body', 'params', 'headers', 'query'].forEach((k) => {
      if (req[k]) {
        req[k] = sanitize(req[k], options);
      }
    });
    next();
  };
}

module.exports = {
  xss: middleware,
  sanitize,
};
