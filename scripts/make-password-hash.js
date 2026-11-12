const bcrypt = require('bcryptjs');
const password = process.argv[2];
if (!password || password.length < 14) {
  console.error('Usage: node scripts/make-password-hash.js "your-long-password"');
  console.error('Use a unique password of at least 14 characters.');
  process.exit(1);
}
console.log(bcrypt.hashSync(password, 12));
