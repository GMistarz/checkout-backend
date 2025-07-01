const bcrypt = require("bcrypt");

bcrypt.hash("cse", 10).then(hash => {
  console.log("Hashed password:", hash);
});