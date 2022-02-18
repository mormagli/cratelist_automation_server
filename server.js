'use strict';

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');

const verifyToken = require('./middleware/jwt');
const authRouter  = require('./routers/auth-router');

const db = require('./model');
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
const { PORT, MONGODB_URI, } = require('./config');

const app = express();

var corsOptions = {
  origin: 'http://localhost:8081'
};

app.use(cors(corsOptions));


// parse requests
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// setup logging
app.use(morgan(process.env.NODE_ENV === 'development' ? 'dev' : 'common', {
  skip: () => process.env.NODE_ENV === 'test'
}));

app.use('/api/auth', authRouter);

// skeleton get
app.get('/', (req, res) => {
  res.json({ message: 'hello there' });
});

// protected get
app.get('/protected', verifyToken, (req, res) => {
  let token = req.headers['x-access-token'];
  res.json({ message: 'your token is good!', token });
});

let server;

function runServer(databaseUrl, port = PORT) {

  return new Promise((resolve, reject) => {
    db.mongoose.connect(databaseUrl, (err, client) => {
      if (err) {
        return reject(err);
      }
      console.info(`Connected to: mongodb://${client.host}:${client.port}/${client.name}`);

      server = app.listen(port, () => {
        console.log(`App is listening on port ${port}`);
        resolve();
      })
        .on('error', err => {
          db.mongoose.disconnect();
          reject(err);
        });
    });
  });
}

function closeServer() {
  return db.mongoose.disconnect().then(() => {
    return new Promise((resolve, reject) => {
      console.log('Closing server');
      server.close(err => {
        if (err) {
          return reject(err);
        }
        resolve();
      });
    });
  });
}

app.use((req, res, next) => {
  const err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// Custom Error Handler
app.use((err, req, res, next) => {
  if (err.status) {
    const errBody = Object.assign({}, err, { message: err.message });
    res.status(err.status).json(errBody);
  } else {
    if(process.env.NODE_ENV !== 'test') {
      console.error(err);
    }
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

if (require.main === module) {
  runServer(MONGODB_URI).catch(err => console.error(err));
}

module.exports = { app, runServer, closeServer };

