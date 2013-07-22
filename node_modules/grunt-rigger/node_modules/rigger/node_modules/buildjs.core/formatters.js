/**
# formatters

Formatting helper functions.
*/
var regexes = require('./regexes'),
    reTrailingWhitespace = regexes.trailingWhitespace;

/**
## stripTrailingWhitespace
*/
exports.stripTrailingWhitespace = function(line) {
    return line.replace(reTrailingWhitespace, '');
};

/**
## normlizeExt
*/
exports.normalizeExt = function(ext) {
    return (ext || '').replace(regexes.leadingDot, '').toLowerCase();
};