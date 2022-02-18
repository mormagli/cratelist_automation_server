'use strict';

require('dotenv').config();

module.exports = {
  PORT: process.env.PORT || 8080,
  CLIENT_ORIGIN: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
  MONGODB_URI:   process.env.DATABASE_URL,
  TEST_DATABASE_URL: 'mongodb://localhost/crate88server',
  JWT_SECRET : process.env.JWT_SECRET,
  JWT_EXPIRY : process.env.JWT_EXPIRY || '7d'
};
