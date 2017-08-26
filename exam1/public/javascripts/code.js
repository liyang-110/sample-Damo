var vue = new Vue({
    el: '#app',
    data: {
        username: '',
        password: '',
        message: ''
    },
    methods: {
        submit: function() {
            var xmlhttp;
            if (window.XMLHttpRequest) {
                //  IE7+, Firefox, Chrome, Opera, Safari 浏览器执行代码
                xmlhttp = new XMLHttpRequest();
            } else {
                // IE6, IE5 浏览器执行代码
                xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
            }
            xmlhttp.onreadystatechange = function() {
                if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
                    this.message = xmlhttp.responseText;
                    console.log('success');
                } else {
                    console.log('err');
                }
                var uri_str = "/login?user=" + this.username + "&pwd=" + this.password;
                console.log(uri_str);
                xmlhttp.open("GET", uri_str, true);
                xmlhttp.send();
            }
        }
    }
});