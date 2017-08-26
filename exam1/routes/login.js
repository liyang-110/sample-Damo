var express = require('express');
var router = express.Router();
var mysql = require('mysql');
var connect = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'will1314', //你的数据库密码
    port: 3306,
    database: 'exam1' //你的数据库名称
});

router.get('/', function(req, res, next) {
    var _user = req.query.user;
    var _pwd = req.query.pwd;
    var sql = 'SELECT _name,_pwd FROM e_user where _name = "' + _user + '"';
    connect.query(sql, function(err, result) {
        console.log('查询结束');
        if (err) {
            console.log('[SELECT ERROR] - ', err.message);
        }
        if (result.length == 0) {
            res.contentType = "application/json";
            res.end(JSON.stringify({ 'code': 'err', 'msg': 'user not found' }));
        } else {
            if (result[0]._name == _user && result[0]._pwd == _pwd) {
                res.contentType = "text/html";
                res.end(JSON.stringify({ 'code': 'ok', 'msg': '登录成功' }));
            } else {
                res.contentType = "application/json";
                res.end(JSON.stringify({ 'code': 'err', 'msg': 'password error' }));
            }
        }
        console.log(result);
    });
});

module.exports = router;