"use strict";

const sanitizeHtml = require("sanitize-html");

const initializeOptions = (options) => {
  const sanitizerOptions = {};
  if (Array.isArray(options.allowedTags) && options.allowedTags.length > 0) {
    sanitizerOptions.allowedTags = options.allowedTags;
  }
  return {
    allowedKeys:
      (Array.isArray(options.allowedKeys) && options.allowedKeys) || [],
    sanitizerOptions,
  };
};

const sanitize = (options, data) => {
  if (typeof data === "string") {
    return sanitizeHtml(data, options.sanitizerOptions);
  }
  if (Array.isArray(data)) {
    return data.map((item) => {
      if (typeof item === "string") {
        return sanitizeHtml(item, options.sanitizerOptions);
      }
      if (Array.isArray(item) || typeof item === "object") {
        return sanitize(options, item);
      }
      return item;
    });
  }
  if (typeof data === "object") {
    Object.keys(data).forEach((key) => {
      if (options.allowedKeys.includes(key)) {
        return;
      }
      const item = data[key];
      if (typeof item === "string") {
        data[key] = sanitizeHtml(item, options.sanitizerOptions);
      } else if (Array.isArray(item) || typeof item === "object") {
        data[key] = sanitize(options, item);
      }
    });
  }
  return data;
};

function middleware(options = {}) {
  options = initializeOptions(options);
  return (req, res, next) => {
    ["body", "params", "headers", "query"].forEach((k) => {
      if (req[k]) {
        req[k] = sanitize(options, req[k]);
      }
    });
    next();
  };
}

module.exports = middleware;
