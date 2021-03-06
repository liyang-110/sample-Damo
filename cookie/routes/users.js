var express = require('express');
var router = express.Router();
var crypto = require('crypto');

function hashPW(userName, pwd) {
    var hash = crypto.createHash('md5');
    hash.update(userName + pwd);
    return hash.digest('hex');
}

// just for tutorial, it's bad really
var userdb = [{
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

function getLastLoginTime(userName) {
    for (var i = 0; i < userdb.length; ++i) {
        var user = userdb[i];
        if (userName === user.userName) {
            return user.last;
        }
    }
    return "";
}

function updateLastLoginTime(userName) {
    for (var i = 0; i < userdb.length; ++i) {
        var user = userdb[i];
        if (userName === user.userName) {
            user.last = Date().toString();
            return;
        }
    }
}

function authenticate(userName, hash) {
    //用户名和密码是否存在。
    for (var i = 0; i < userdb.length; ++i) {
        var user = userdb[i];
        if (userName === user.userName) {
            if (hash === user.hash) {
                return 0;
            } else {
                return 1;
            }
        }
    }

    return 2;
}

function isLogined(req) {
    if (req.cookies["account"] != null) {
        var account = req.cookies["account"];
        var user = account.account;
        var hash = account.hash;
        if (authenticate(user, hash) == 0) {
            console.log(req.cookies.account.account + " had logined.");
            return true;
        }
    }
    return false;
};

router.requireAuthentication = function(req, res, next) {
    //用户选择login
    if (req.path == "/login") {
        next();
        return;
    }

    //其他操作，登录过
    if (req.cookies["account"] != null) {
        var account = req.cookies["account"];
        var user = account.account;
        var hash = account.hash;
        if (authenticate(user, hash) == 0) {
            console.log(req.cookies.account.account + " had logined.");
            next();
            return;
        }
    }

    //其他操作，没有登录过，重定向到login
    console.log("not login, redirect to /login");
    res.redirect('/login?' + Date.now());
};

router.post('/login', function(req, res, next) {
    var userName = req.body.login_username;
    var hash = hashPW(userName, req.body.login_password);
    console.log("login_username - " + userName + " password - " + req.body.login_password + " hash - " + hash);
    switch (authenticate(userName, hash)) {
        case 0: //success
            var lastTime = getLastLoginTime(userName);
            updateLastLoginTime(userName);
            console.log("login ok, last - " + lastTime);
            res.cookie("account", { account: userName, hash: hash, last: lastTime }, { maxAge: 60000 });
            res.redirect('/profile?' + Date.now());
            console.log("after redirect");
            break;
        case 1: //password error
            console.log("password error");
            res.render('login', { msg: "密码错误" });
            break;
        case 2: //user not found
            console.log("user not found");
            res.render('login', { msg: "用户名不存在" });
            break;
    }
});

router.get('/login', function(req, res, next) {
    console.log("cookies:");
    console.log(req.cookies);
    if (isLogined(req)) {
        res.redirect('/profile?' + Date.now());
    } else {
        res.render('login');
    }
});

router.get('/logout', function(req, res, next) {
    res.clearCookie("account");
    res.redirect('/login?' + Date.now());
});

router.get('/profile', function(req, res, next) {
    res.render('profile', {
        msg: "您登录为：" + req.cookies["account"].account,
        title: "登录成功",
        lastTime: "上次登录：" + req.cookies["account"].last
    });
});

module.exports = router;
