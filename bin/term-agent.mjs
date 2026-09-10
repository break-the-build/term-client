#!/usr/bin/env node
import { main } from "../client.mjs";
main()
  .then((result) => console.log(JSON.stringify(result)))
  .catch((error) => {
    console.error(JSON.stringify({ status: "error", message: error.message }));
    process.exitCode = 1;
  });
