'use strict';

require('dotenv').config();

const db = require('../model');
const config = require('../config');
const {app} = require('../server');

const User = db.user;

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const verifyToken = require('../middleware/jwt');


const chai = require('chai');
const expect = chai.expect;
const should = chai.should();


describe('Auth endpoints', function () {
  const username = 'exampleUser';
  const password = 'examplePass';
  const id = '5b4665532f7f8c7a440cc7e2';
  
  beforeEach(function () {
    return User.create({
      username,
      id,
      password: bcrypt.hashSync(password, 8)
    });
      
  });
  
  afterEach(function () {
    return User.deleteOne({});
  });
  
  describe('/api/auth/login', function () {
    it('Should reject requests with no credentials', function () {
      return chai
        .request(app)
        .post('/api/auth/login')
        .send({  })
        .then(res => { expect(res).to.have.status(422); })
        .catch(err => {throw err;});
    });
    it('Should reject requests with incorrect usernames', function () {
      return chai
        .request(app)
        .post('/api/auth/login')
        .send({ username: 'wrongUsername', password })
        .then(res => { expect(res).to.have.status(404); })
        .catch(err => {throw err;});
    });
    it('Should reject requests with incorrect passwords', function () {
      return chai
        .request(app)
        .post('/api/auth/login')
        .send({ username, password: 'wrongPassword' })
        .then( res =>{ expect(res).to.have.status(401);})
        .catch(err => {throw err;});
    });
    it('Should return a valid auth token', function () {
      return chai
        .request(app)
        .post('/api/auth/login')
        .send({ username, password, id})
        .then(res => {
          expect(res).to.have.status(200);
          expect(res.body).to.be.an('object');
          const token = res.body.accessToken;
          expect(token).to.be.a('string');
          const payload = jwt.verify(token, config.JWT_SECRET, {
            algorithm: ['HS256']
          });
          expect(payload.sub).to.be.a('string', username);
        })
        .catch(err => {throw err;});
    });
  });

      
  describe('/api/auth/refresh', function () {
    it('Should reject requests with no credentials', function () {
      return chai
        .request(app)
        .post('/api/auth/refresh')
        .then(res =>{ expect(res).to.have.status(403); })
        .catch(err => {throw err;});
    });
    it('Should reject requests with an invalid token', function () {
      const token = 
      jwt.sign({id: id}, 'Wrong Secret!', {
        subject: username,
        expiresIn: config.JWT_EXPIRY,
        algorithm: 'HS256'
      });
      
      return chai
        .request(app)
        .post('/api/auth/refresh')
        .set('x-access-token', token)
        .send({userId: id})
        .then(res => { expect(res).to.have.status(401); })
        .catch(err => {throw err;});
    });
    it('Should reject requests with an expired token', function () {

      const token = jwt.sign({id: id}, config.JWT_SECRET, {
        subject: username,
        expiresIn: '.01s',
        algorithm: 'HS256'
      });

      return chai
        .request(app)
        .post('/api/auth/refresh')
        .set('x-access-token', token)
        .then(res => { expect(res).to.have.status(401); })
        .catch(err => {throw err;});
        
    });
    it('Should return a valid auth token with a newer expiry date', function () {
      
      const token = jwt.sign({id: id}, config.JWT_SECRET, {
        subject: username,
        expiresIn: config.JWT_EXPIRY,
        algorithm: 'HS256'
      });
      const decoded = jwt.decode(token);

      return chai
        .request(app)
        .post('/api/auth/refresh')
        .set('x-access-token', token)
        .then(res => {
          expect(res).to.have.status(200);
          expect(res.body).to.be.an('object');
          const token = res.body.accessToken;
          expect(token).to.be.a('string');
          const payload = jwt.verify(token, config.JWT_SECRET, {
            algorithm: ['HS256']
          });
          expect(payload.sub).to.be.a('string', username);
          expect(payload.exp).to.be.at.least(decoded.exp);
        })
        .catch(err => {throw err;});
    });
  });
});  
      





