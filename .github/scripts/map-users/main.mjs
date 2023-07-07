import * as fs from 'fs';
import * as yaml from 'js-yaml';

export default function message(payload) {
  const mappingFile = new URL("../../matrix-users.yaml", import.meta.url);
  const mappings = yaml.load(fs.readFileSync(mappingFile))?.mappings;

  let users = [];
  let matrix_users = [];

  for (let user of payload?.pull_request?.requested_reviewers ) {
    // get user id
    const login = user?.login;
    if (login === undefined) {
      continue;
    }

    // record for logging
    users.push(login);

    // map
    let m = mappings?.[login];
    if (m !== undefined) {
      matrix_users.push(m);
    }
  }

  console.log("Users:", users)
  console.log("Matrix Users:", matrix_users)

  if (!matrix_users.length) {
    return undefined;
  }

  let s = (matrix_users.length > 1) ? "s" : "";

  matrix_users = matrix_users.join(", ")

  return `Assigned ${matrix_users} as reviewer${s} for PR: ${payload?.pull_request?.html_url}`
}


