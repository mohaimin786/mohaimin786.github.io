npm install express sqlite3 body-parser
sqlite3 bhss.db "SELECT * FROM submissions;"
sqlite3 bhss.db "SELECT id, fullName, email FROM submissions;"
chmod 644 bhss.db
touch bhss.db
ls -la bhss.db
chmod 644 bhss.db
file bhss.db
sqlite3 bhss.db ".schema submissions"
ls -la | grep -E 'bhss.db-(shm|wal)'
sqlite3 bhss.db "INSERT INTO submissions (fullName, email) VALUES ('MANUAL TEST', 'test@test.com'); SELECT last_insert_rowid();"
sqlite3 bhss.db "SELECT id, fullName, datetime(timestamp) FROM submissions;"
npm install express sqlite3 ws
touch bhss.db
npm install body-parser express sqlite3 ws
npm list body-parser
ls -lh bhss.db
sqlite3 bhss.db "SELECT * FROM submissions;"
ls -lh bhss.db
sqlite3 bhss.db "SELECT * FROM submissions ORDER BY id DESC LIMIT 1;"
curl -X POST http://localhost:3000/api/submit -H "Content-Type: application/json" -d '{"fullName":"Test User","email":"test@example.com"}'
curl http://localhost:3000/api/debug-db
curl http://localhost:3000/api/debug-db
curl http://localhost:3000/api/submissions
sqlite3 bhss.db "INSERT INTO submissions (fullName, email) VALUES ('TEST ENTRY', 'test@test.com');"
SELECT * FROM submissions;
SELECT * FROM submissions;
npm install mongodb mongoose
mongod
npm install mongodb mongoose express body-parser
mongo
npm install nedb
pm install express-session bcryptjs helmet express-rate-limit
npm install express-session
rm -rf node_modules package-lock.json
npm install
npm list express-session
rm -rf node_modules package-lock.json
rm -rf node_modules package-lock.json
npm install
npm install helmet
npm install helmet express-rate-limit
refresh
npm install bcryptjs
refresh
npm install
refresh
refresh
refresh
refresh
refresh
refresh
