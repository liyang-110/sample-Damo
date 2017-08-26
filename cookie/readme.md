## 一个登录的示例
这个示例会用到Cookie、HTML表单、POST数据体(body)解析。
这个版本使用JSON数据,下个版本使用mysql和mongodb
示例准备

### 1. 使用express创建应用

就下面的命令序列：
```
express LoginDemo
cd LoginDemo
cnpm install
```
### 2. 登录页面

登录页面的jade模板为`views/login.jade`，内容如下：
```
doctype html
html
  head
    meta(charset='UTF-8')
    title Login
    link(rel='stylesheet', href='/stylesheets/login.css')
  body
    .form-container
      p.form-header Login
      form(action='login', method='POST', align='center')
        table
          tr
            td
              label(for='user') User：
            td
              input#user(type='text', name='login_username')
          tr
            td
              label(for='pwd') Password：
            td
              input#pwd(type='password', name='login_password')
          tr
            td(colspan='2', align='right')
              input(type='submit', value='Login')

    //用于显示登录错误信息，msg变量由应用程序传入。          
    p #{msg}  
```
`/public/stylesheets/login.css`文件,设置login.html的样式，内容如下：
```
form {
  margin: 12px;
}
a {
  color: #00B7FF;
}

div.form-container {
  display: inline-block;
  border: 6px solid steelblue;
  width: 280px;
  border-radius: 10px;
  margin: 12px;
}

p.form-header {
  margin: 0px;
  font: 24px bold;
  color: white;
  background: steelblue;
  text-align: center;
}

input[type=submit]{
  font: 18px bold;
  width: 120px;
  margin-left: 12px;
}
```

### 3. profile页面

登录成功后会显示配置页面，/views/profile.jade页面内容：
```
doctype html
html
  head
    meta(charset='UTF-8')
    title= title
  body
    p #{msg}
    p #{lastTime}
    p 
      a(href='/logout') 退出
```
profile页面显示一条登录成功的消息，还显示上次登录时间，最后提供了一个退出链接。

### 4. app.js改动

app.js，用户在没有登录时访问网站自动跳转到login页面。内容如下：
```
var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var users = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.all('*', users.requireAuthentication);
app.use('/', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});


module.exports = app;
```
### 5. users.js
/routes/user.js
把认证、登录、登出等逻辑放在里面，首先要把users.js转为UTF-8编码.内容：
```
var express = require('express');
var router = express.Router();
var crypto = require('crypto');

function hashPW(userName, pwd){
  var hash = crypto.createHash('md5');
  hash.update(userName + pwd);
  return hash.digest('hex');
}

// just for tutorial, it's bad really
var userdb = [
    {
      userName: "admin",
      hash: hashPW("admin", "123456"),
      last: ""
    },
    {
      userName: "qingcong",
      hash: hashPW("qingcong", "qc123"),
      last: ""
    }
  ];

function getLastLoginTime(userName){
  for(var i = 0; i < userdb.length; ++i){
    var user = userdb[i];
    if(userName === user.userName){
      return user.last;
    }
  }
  return "";
}

function updateLastLoginTime(userName){
  for(var i = 0; i < userdb.length; ++i){
    var user = userdb[i];
    if(userName === user.userName){
      user.last = Date().toString();
      return;
    }
  }
}

function authenticate(userName, hash){

  for(var i = 0; i < userdb.length; ++i){
    var user = userdb[i];
    if(userName === user.userName){
      if(hash === user.hash){
          return 0;
      }else{
          return 1;
      }
    }
  }

  return 2;
}

function isLogined(req){
  if(req.cookies["account"] != null){
    var account = req.cookies["account"];
    var user = account.account;
    var hash = account.hash;
    if(authenticate(user, hash)==0){
      console.log(req.cookies.account.account + " had logined.");
      return true;
    }
  }
  return false;
};

router.requireAuthentication = function(req, res, next){
  if(req.path == "/login"){
    next();
    return;
  }

  if(req.cookies["account"] != null){
    var account = req.cookies["account"];
    var user = account.account;
    var hash = account.hash;
    if(authenticate(user, hash)==0){
      console.log(req.cookies.account.account + " had logined.");
      next();
      return;
    }
  }
  console.log("not login, redirect to /login");
  res.redirect('/login?'+Date.now());
};

router.post('/login', function(req, res, next){
  var userName = req.body.login_username;
  var hash = hashPW(userName, req.body.login_password);
  console.log("login_username - " + userName + " password - " + req.body.login_password + " hash - " + hash);
  switch(authenticate(userName, hash)){
  case 0: //success
    var lastTime = getLastLoginTime(userName);
    updateLastLoginTime(userName);
    console.log("login ok, last - " + lastTime);
    res.cookie("account", {account: userName, hash: hash, last: lastTime}, {maxAge: 60000});
    res.redirect('/profile?'+Date.now());
    console.log("after redirect");
    break;
  case 1: //password error
    console.log("password error");
    res.render('login', {msg:"密码错误"});
    break;
  case 2: //user not found
    console.log("user not found");
    res.render('login', {msg:"用户名不存在"});
    break;
  }
});

router.get('/login', function(req, res, next){
  console.log("cookies:");
  console.log(req.cookies);
  if(isLogined(req)){
    res.redirect('/profile?'+Date.now());
  }else{
    res.render('login');
  }
});

router.get('/logout', function(req, res, next){
  res.clearCookie("account");
  res.redirect('/login?'+Date.now());
});

router.get('/profile', function(req, res, next){
  res.render('profile',{
    msg:"您登录为："+req.cookies["account"].account, 
    title:"登录成功",
    lastTime:"上次登录："+req.cookies["account"].last
  });
});

module.exports = router;
```
在users.js中内置了两个账号，admin和qingcong，登录时就验证这两个账号，不对就报错。后期需要把帐号存储到数据库中.
### 执行
执行“npm start”，然后在浏览器里打开“http://localhost:3000”，可以看到下面的效果：

view-logindemo.png

折腾几次，登录，退出，再次登录，效果如下：

view-logindemo-profile.png

好啦，这就是这个示例的效果。接下来我们来解释一下用到概念和部分代码。

处理POST正文数据

我们在示例中使用了HTML表单来接收用户名和密码，当input元素的类型为submit时，点击它，浏览器会把表单内的数据按一定的格式组织之后编码进body，POST到指定的服务器地址。用户名和密码，在服务器端，可以通过HTML元素的名字属性的值找出来。

服务器解析表单数据这一过程，我们不用担心，用了express的body-parser中间件，它会帮我们做这件事，只要做简单的配置即可。而且这些配置代码，express generator都帮我们完成了，如下：

//加载body-parser模块
var bodyParser = require('body-parser');
...
//应用中间件
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
我们处理/login路径上的POST请求的代码在users.js里，从“router.post(‘/login’…”开始（94行，要是markdown能自动给代码插入行号就好了）。引用登录表单内的用户名的代码如下：

var userName = req.body.login_username;
注意到了吧，express.Request对象req内有解析好的body，我们使用login_username来访问用户名。而login_username就是我们在HTML里的input元素的name属性的值。就这么关联的。password也类似。

cookie

cookie，按我的理解，就是服务器发给浏览器的一张门票，要访问服务器内容，可以凭票入场，享受某种服务。服务器可以在门票上记录一些信息，从技术角度讲，想记啥记啥。当浏览器访问服务器时，HTTP头部把cookie信息带到服务器，服务器解析出来，校验当时记录在cookie里的信息。

HTTP协议本身是无状态的，而应用服务器往往想保存一些状态，cookie应运而生，由服务器颁发，通过HTTP头部传给浏览器，浏览器保存到本地。后续访问服务器时再通过HTTP头部传递给服务器。这样的交互，服务器就可以在cookie里记录一些用户相关的信息，比如是否登录了，账号了等等，然后就可以根据这些信息做一些动作，比如我们示例中的持久登录的实现，就利用了cookie。还有一些电子商务网站，实现购物车时也可能用到cookie。

cookie存储的是一些key-value对。在express里，Request和Response都有cookie相关的方法。Request实例req的cookies属性，保存了解析出的cookie，如果浏览器没发送cookie，那这个cookies对象就是一个空对象。

express有个插件，cookie-parser，可以帮助我们解析cookie。express生成的app.js已经自动为我们配置好了。相关代码：

var cookieParser = require('cookie-parser');
...
app.use(cookieParser());
express的Response对象有一个cookie方法，可以回写给浏览器一个cookie。

下面的代码发送了一个名字叫做“account”的cookie，这个cookie的值是一个对象，对象内有三个属性。

res.cookie("account", {account: userName, hash: hash, last: lastTime}, {maxAge: 60000});
res.cookie()方法原型如下：

res.cookie(name, value [, options])
文档在这里：http://expressjs.com/4x/api.html#res.cookie。

浏览器会解析HTTP头部里的cookie，根据过期时间决定保存策略。当再次访问服务器时，浏览器会把cookie带给服务器。服务器使用cookieParser解析后保存在Request对象的cookies属性里，req.cookies本身是一个对象，解析出来的cookie，会被关联到req.cookies的以cookie名字命名的属性上。比如示例给cookie起的名字叫account，服务端解析出的cookie，就可以通过req.cookies.account来访问。注意req.cookies.account本身既可能是简单的值也可能是一个对象。在示例中通过res.cookie()发送的名为account的cookie，它的值是一个对象，在这种情况下，服务器这边从HTTP请求中解析出的cookie也会被组装成一个对象，所以我们通过req.cookies.account.account就可以拿到浏览器通过cookie发过来的用户名。但如果浏览器没有发送名为“account”的cookie，那req.cookies.account.hash这种访问就会抛异常，所以我在代码里使用req.cookies[“account”]这种方式来检测是否有account这个cookie。

持久登录

如果用户每次访问一个需要鉴权的页面都要输入用户名和密码来登录，那就太麻烦了。所以，很多现代的网站都实现了持久登录。我的示例使用cookie简单实现了持久登录。

在处理/login路径上的POST请求时，如果登录成功，就把用户名、一个hash值、还有上次登录时间保存在cookie里，并且设置cookie的有效期为60秒。这样在60秒有效期内，浏览器后续的访问就会带cookie，服务端代码从cookie里验证用户名和hash值，让用户保持登录状态。当过了60秒，浏览器就不再发送cookie，服务端就认为需要重新登录，将用户重定向到login页面。

现在服务端的用户信息就简单的放在js代码里了，非常丑陋，下次我们引入mongodb，把用户信息放在数据库里。