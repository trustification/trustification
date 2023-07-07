import * as fs from 'fs';
import message from "./main.mjs";

const github = JSON.parse(fs.readFileSync('payload.json'))?.github;

const output = message(github.event)

console.log("Output:", output)
