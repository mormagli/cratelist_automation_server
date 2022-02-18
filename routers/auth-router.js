'use strict';

const express = require('express');
const router = express.Router();
const verifyToken = require('../middleware/jwt');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const config = require('../config');

const db = require('../model');
const User = db.user;

const createAuthToken = function(user) {
  return jwt.sign({id: user.id}, config.JWT_SECRET, {
    subject: user.username,
    expiresIn: config.JWT_EXPIRY,
    algorithm: 'HS256'
  });
};

const validateInput = function(req){

  const requiredFields = ['username', 'password'];
  const missingField = requiredFields.find(field => !(field in req.body));
  
  if (missingField || Object.getOwnPropertyNames(req.body).length === 0) {
    return {
      code: 422,
      reason: 'ValidationError',
      message: 'Missing field',
      location: missingField
    };
  }
  
  const stringFields = ['username', 'password'];
  const nonStringField = stringFields.find(
    field => field in req.body && typeof req.body[field] !== 'string'
  );
  
  if (nonStringField) {
    return {
      code: 422,
      reason: 'ValidationError',
      message: 'Incorrect field type: expected string',
      location: nonStringField
    };
  }
  
  const explicityTrimmedFields = ['username', 'password'];
  const nonTrimmedField = explicityTrimmedFields.find(
    field => req.body[field].trim() !== req.body[field]
  );
  
  if (nonTrimmedField) {
    return {
      code: 422,
      reason: 'ValidationError',
      message: 'Cannot start or end with whitespace',
      location: nonTrimmedField
    };
  }
  
  const sizedFields = {
    username: { min: 1 },
    password: { min: 6, max: 72}
  };
  
  const tooSmallField = Object.keys(sizedFields).find(
    field =>
      'min' in sizedFields[field] &&
          req.body[field].trim().length < sizedFields[field].min
  );
  const tooLargeField = Object.keys(sizedFields).find(
    field =>
      'max' in sizedFields[field] &&
          req.body[field].trim().length > sizedFields[field].max
  );
      
  if (tooSmallField || tooLargeField) {
    return {
      code: 422,
      reason: 'ValidationError',
      message: tooSmallField
        ? `Must be at least ${sizedFields[tooSmallField]
          .min} characters long`
        : `Must be at most ${sizedFields[tooLargeField]
          .max} characters long`,
      location: tooSmallField || tooLargeField
    };
  }
  return undefined;
};


router.post('/register', (req, res) => {

  var status_err = validateInput(req);
  if (status_err){
    return res.status(422).json(status_err);
  }

  let {username, password } = req.body;
  // Username and password come in pre-trimmed, otherwise we don't get here
        
  return User.find({username})
    .count()
    .then(count => {
      if (count > 0) {
        // There is an existing user with the same username
        return Promise.reject({
          code: 422,
          reason: 'ValidationError',
          message: 'Username already taken',
          location: 'username'
        });
      }
      else {
        // If there is no existing user, make a new one
        return User.create({
          username,
          password: bcrypt.hashSync(password, 8)
        });
      }
    })
    .then(user => {
      return res.status(201).json(
        {username: user.username || '',
          _id: user._id,
          role: user.role}
      );
    })
    .catch(err => {
      // Forward validation errors on to the client, otherwise give a 500
      // error because something unexpected has happened
      
      if (err.reason === 'ValidationError') {
        return res.status(err.code).json(err);
      }
      res.status(500).json({code: 500, message: 'Internal server error'});
    });

});

router.post('/login', (req, res) => {

  var status_err = validateInput(req);
  if (status_err){
    return res.status(422).json(status_err);
  }

  User.findOne({
    username: req.body.username
  })
    .exec((err, user) => {
      if (err) {
        res.status(500).send({ message: err });
        return;
      }
    
      if (!user) {
        return res.status(404).send({ message: 'User Not found.' });
      }
    
      var passwordIsValid = bcrypt.compareSync(
        req.body.password,
        user.password
      );
    
      if (!passwordIsValid) {
        return res.status(401).send({
          accessToken: null,
          message: 'Invalid Password!'
        });
      }

      const token = createAuthToken(user);
      var authorities = [];
    
      for (let i = 0; i < user.roles.length; i++) {
        authorities.push('ROLE_' + user.roles[i].toUpperCase());
      }
      res.status(200).send({
        id: user._id,
        username: user.username,
        email: user.email,
        roles: authorities,
        accessToken: token
      });
    });
    
});

router.post('/refresh', verifyToken, (req, res) => {
  User.findOne({
    id: req.userId,
  })
    .exec((err,user) =>{
      if (err) {
        res.status(500).send({ message: err });
        return;
      }
      const token = createAuthToken(user);
      res.status(200).send({
        id: user.id,
        username: user.username,
        email: user.email,
        accessToken: token
      });
    });


});

module.exports = router;
