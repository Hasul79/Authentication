const express = require('express')
const sqlite3 = require('sqlite3').verbose();
const bodyparser = require('body-parser')
const jwt = require('jsonwebtoken');
const bcrypt = require("bcrypt");
const jsonparser = bodyparser.json()
const app = express()
const port = 3000

app.use(jsonparser)

let db = new sqlite3.Database('main.db')
db.run("CREATE TABLE IF NOT EXISTS users(username TEXT, password TEXT)")

//------------------------------------------------------------
app.get('/', authenticateToken, (req, res) => {
  res.send('Hello World!')
})

//----------------------------------------------------------

const SECRET = "somerandomsecret"
function generateAccessToken(username) {
    return jwt.sign(username, SECRET, { expiresIn: '36000s' });
}

//------------------------------------------------------------

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  
  if (token == null) return res.sendStatus(401)
  
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
  
    req.user = user
  
    next()
  })
  }
  app.post('/register', async (req, res) => {
    const content = req.body 
    const username = content["username"]
    const password = content["password"]
    const salt = await bcrypt.genSalt(10)
    const hashed_password = await bcrypt.hash(password, salt)
    const new_user = {
      username: username,
      password: hashed_password
    }
    let sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    db.run(sql, username,hashed_password, function(err){
          if(err){
              res.send(JSON.stringify({status: "Error Reigstering"}))
          }
          res.send(JSON.stringify({status: "User Created"}))
      })  
  
    
  })
  
  app.post('/login', (req, res) => {
    const content = req.body 
    const username = content["username"]
    const password = content["password"]
    const token = generateAccessToken({ username: username});
  
    let sql = "SELECT * from users WHERE username = ?"
    db.get(sql,[username], async function(err, row){
      console.log(row)
      if(row == undefined ){
          res.send(JSON.stringify({status: "Wrong credentials"}));
      }
      else if(username == row.username && await bcrypt.compare(password, row.password)) {
          res.send(JSON.stringify({jwt_token: token}));
      }else {
          res.send(JSON.stringify({status: "Wrong credentials"}));
      }  
    })
  })
  //--------------------------------------------------------------
  
  app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
  })