'use strict';

const sanitize = require('./lib/sanitize');

function middleware(options = {}) {
  return (req, res, next) => {
    ['body', 'params', 'headers'].forEach((k) => {
      if (req[k]) {
        req[k] = sanitize(req[k], options);
      }
    });
    const sanitizedQuery = sanitize(req.query, options);
    Object.defineProperty(req, 'query', {
      value: sanitizedQuery,
      writable: false,
      configurable: true,
      enumerable: true,
    });
    next();
  };
}

module.exports = {
  xss: middleware,
  sanitize,
};
