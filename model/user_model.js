'use strict';

const mongoose = require('mongoose');

const User = mongoose.model(
  'User',
  new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    roles: 
      {
        type: String,
        default: 'User'
      }
    
  })
);

module.exports = User;
