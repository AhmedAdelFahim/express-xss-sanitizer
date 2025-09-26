'use strict';

const sanitizeHtml = require('sanitize-html');

const MAX_DEPTH = 100;

function hasOwn(object, key) {
  const keys = Reflect.ownKeys(object).filter((item) => typeof item !== 'symbol');
  return keys.includes(key);
}

const initializeOptions = (options) => {
  const sanitizerOptions = {};
  if (hasOwn(options, 'allowedTags') && Array.isArray(options.allowedTags) && options.allowedTags.length > 0) {
    sanitizerOptions.allowedTags = options.allowedTags;
  }

  if (hasOwn(options, 'allowedAttributes') && Object.keys(options.allowedAttributes).length > 0) {
    sanitizerOptions.allowedAttributes = options.allowedAttributes;
  }

  return {
    allowedKeys: (hasOwn(options, 'allowedKeys') && Array.isArray(options.allowedKeys) && options.allowedKeys) || [],
    maxDepth:
      hasOwn(options, 'maxDepth') && typeof options.maxDepth === 'number' && options.maxDepth > 0
        ? options.maxDepth
        : MAX_DEPTH,
    sanitizerOptions,
  };
};

const sanitize = (options, data, currentDepth = 0) => {
  if (currentDepth > options.maxDepth) {
    throw new Error(`Maximum sanitization depth of ${options.maxDepth} exceeded`);
  }
  if (typeof data === 'string') {
    return sanitizeHtml(data, options.sanitizerOptions);
  }
  if (Array.isArray(data)) {
    return data.map((item) => {
      if (typeof item === 'string') {
        return sanitizeHtml(item, options.sanitizerOptions);
      }
      if (Array.isArray(item) || typeof item === 'object') {
        return sanitize(options, item, currentDepth + 1);
      }
      return item;
    });
  }
  if (typeof data === 'object' && data !== null) {
    Object.keys(data).forEach((key) => {
      if (options.allowedKeys.includes(key)) {
        return;
      }
      const item = data[key];
      if (typeof item === 'string') {
        data[key] = sanitizeHtml(item, options.sanitizerOptions);
      } else if (Array.isArray(item) || typeof item === 'object') {
        data[key] = sanitize(options, item, currentDepth + 1);
      }
    });
  }
  return data;
};

const prepareSanitize = (data, options = {}) => {
  options = initializeOptions(options);
  return sanitize(options, data);
};

module.exports = prepareSanitize;
