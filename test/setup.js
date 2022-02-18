'use strict';

require('dotenv').config();
const {TEST_DATABASE_URL} = require('../config');
const { mongoose } = require('../model');
const db = require('../model');
const { app, runServer, closeServer } = require('../server');

const chai = require('chai');
const chaiHttp = require('chai-http');
chai.use(chaiHttp);



process.env.NODE_ENV = 'test';

exports.mochaHooks = {
  beforeAll() {
    //make sure mongoose uses es6 implementation of promises
    db.mongoose.Promise = global.Promise;
    runServer(TEST_DATABASE_URL);
  },
  afterAll() {
    closeServer();
    //console.warn('Disconnected');
  }

};
