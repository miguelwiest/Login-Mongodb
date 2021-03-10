const express = require('express');
const router = express.Router();
const db = require('../db');
const jwt = require('jsonwebtoken');
const config = require('../config');
const bcrypt = require('bcrypt-nodejs');

const handleToken = (req, res, next) => {
  
  let token = req.headers['authorization'].split(' ')[1];
  jwt.verify(token, config.JWT_KEY, (err, decode) => {
    if (!err) {
      next();
    } else {
      res.status(401).json({
        success: false,
        error: err
      });
    }
  })
}

router.post('/register', (req, res, next) => {
  const { username, email, password } = req.body.userData;

  const hash = bcrypt.hashSync(password, config.SALT_ROUNDS);

  const dataToInsert = {
    name: username,
    email,
    password: hash
  };

  const handler = (err, result) => {
    if (!err) {
      res.json({
        success: true,
        message: 'User registered.',
        data: result
      });
    } else {
      res.json({
        success: false,
        message: 'User not registered.',
        error: err
      });
    }

  }
  db.register(dataToInsert, handler);

});

router.post('/listusers', handleToken, (req, res, next) => {
 
  const handler = (err, result) => {
    if (!err && result != null) {
      result.toArray((err, users) => {
        if(!err){
          res.json({
            success: true,
            message: 'The list of users',
            data: users
          });
        }
      })
    } else {
      res.json({
        success: false,
        message: 'An error happened.',
        error: err
      });
    }
  }

  db.findAll(handler);

})

module.exports = router;
