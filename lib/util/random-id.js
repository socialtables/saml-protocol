"use strict";
const crypto = require("crypto");

/**
 * Creates a random ID for use in XML document references
 */
module.exports = function randomID() {
	return crypto.randomBytes(21).toString("hex");
};
