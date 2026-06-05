// init-db.js — initialise/upgrade the database schema and report what was built.
import { tableNames, profileColumns, DB_PATH } from './db.js';

console.log('DB:', DB_PATH);
console.log('Tables:', tableNames().join(', '));
const cols = profileColumns();
console.log(`profiles columns (${cols.length}):`);
console.log('  ' + cols.join(', '));
console.log('\nSchema initialised OK.');
