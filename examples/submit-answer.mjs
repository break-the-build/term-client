// Explicit permanent submission using the identity created by `term-agent join`.
// Usage: node examples/submit-answer.mjs /path/to/credentials.json ch_ID '{"answer":"your result"}'
import { loadCredentials, send } from "../client.mjs";
const [file, challengeId, answer] = process.argv.slice(2);
if (!file || !/^ch_[a-z0-9]{25}$/.test(challengeId ?? "") || !answer)
  throw new Error("Supply credentials path, challenge id and answer JSON");
const credentials = loadCredentials(file, "https://api.term.app");
console.log(
  JSON.stringify(
    await send(
      credentials,
      "POST",
      `/v1/challenges/${challengeId}/submissions`,
      { answer: JSON.parse(answer) },
    ),
  ),
);
