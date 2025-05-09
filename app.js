var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var cors = require('cors')

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var webauthnRoutes = require('./routes/webauthn');
var citzensRoutes = require('./routes/citizens');
var recordsRoutes = require('./routes/records');
var vehiclesRoutes = require('./routes/vehicles');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(cors({
  origin: 'http://localhost:5173',
  methods: ['GET', 'POST', 'OPTIONS', 'DELETE'],
  credentials: true // Jeśli używasz ciasteczek lub uwierzytelniania
}));

app.use('/', indexRouter);
app.use('/citizens', citzensRoutes);
app.use('/vehicles', vehiclesRoutes);
app.use('/webauthn', webauthnRoutes);
app.use('/records', recordsRoutes);

app.listen(3001, () => {
  console.log(`Serwer działa na http://localhost:3001`);
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
