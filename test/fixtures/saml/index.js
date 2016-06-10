"use strict";

const fs = require("fs");
const path = require("path");

module.exports = function get(fixtureName) {
	const resolvedPath = path.resolve(__dirname, fixtureName);
	return fs.readFileSync(resolvedPath, "utf8");
};
