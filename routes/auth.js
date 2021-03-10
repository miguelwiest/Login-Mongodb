const express = require('express');
const router = express.Router();
const config = require('../config');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt-nodejs');
const db = require('../db');

router.post('/login', (req, res, next) => {
    console.log(req.body)
    const { email, password } = req.body.userData;

    if( email === undefined || password === undefined ){
        res.status(401).json({
            success: false,
            code: 'DD101_API_ERROR_01',
            message: "E-mail and/or password invalid."
        });
    } else {
        const handler = (err, result) => {
            if(!err && result !== null && bcrypt.compareSync(password, result.password)){
                let tokenData = {
                    name: result.name,
                    email: result.email
                }
                let generatedToken = jwt.sign(tokenData, config.JWT_KEY, {  expiresIn: '1m'});
                res.json({
                    success: true,
                    token: generatedToken
                });
            } else {
                res.status(401).json({
                    success: false,
                    code: 'DD101_API_ERROR_02',
                    message: err || 'User does not exists.'
                });
            }
        }
        db.findUser({email}, handler);
    }
});

router.get('/verifytoken', (req, res, next) => {
    let token = req.headers['authorization'].split(' ')[1];
    jwt.verify(token, config.JWT_KEY, (err, decode) => {
        if(!err){
            res.json({
                success: true,
                message: 'Token is valid.'
            });
        } else {
            res.status(401).json({
                success: false,
                error: err
            });
        }
    })
})


module.exports = router;