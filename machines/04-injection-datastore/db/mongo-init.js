// WSTG-INJT-05 (05.6 NoSQL) seed. Synthetic training data only.
db = db.getSiblingDB('lab');

db.users.drop();
db.users.insertMany([
  { user: 'alice', pass: 'Password123!', role: 'user' },
  { user: 'bob',   pass: 'Password123!', role: 'user' },
  { user: 'admin', pass: 'Adm1nPassword!', role: 'admin',
    secret: 'WSTG-M04{nosql_operator_and_where}' }
]);

db.staff.drop();
db.staff.insertMany([
  { name: 'alice', title: 'engineer' },
  { name: 'bob',   title: 'engineer' },
  { name: 'admin', title: 'root', secret: 'WSTG-M04{nosql_operator_and_where}' }
]);