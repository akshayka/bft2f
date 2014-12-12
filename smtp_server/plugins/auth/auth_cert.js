// Base authentication plugin.
// This cannot be used on its own. You need to inherit from it.
// See plugins/auth/flat_file.js for an example.

var crypto = require('crypto');
var utils = require('./utils');
var AUTH_COMMAND = 'AUTH';
var AUTH_METHOD_CRAM_CERT = 'CRAM-CERT';
var LOGIN_STRING1 = 'VXNlcm5hbWU6'; //UserLogin: base64 coded
var LOGIN_STRING2 = 'UGFzc3dvcmQ6'; //Password: base64 coded
var fs = require('fs');

exports.hook_capabilities = function (next, connection) {
    // Don't offer AUTH capabilities unless session is encrypted
    if (connection.using_tls) { return next(); }
    if (connection.notes.authenticated) { return next();}

    var methods = [ 'CRAM-CERT' ];
    connection.capabilities.push('AUTH ' + methods.join(' '));
    connection.notes.allowed_auth_methods = methods;
    next();
};

// Override this at a minimum. Run cb(passwd) to provide a password.
exports.get_plain_passwd = function (user, cb) {
    return cb();
};

exports.hook_unrecognized_command = function (next, connection, params) {
    var plugin = this;
    if(params[0].toUpperCase() === AUTH_COMMAND && params[1]) {
        return plugin.select_auth_method(next, connection, params.slice(1).join(' '));
    }
    if (!connection.notes.authenticating) { return next(); }

    var am = connection.notes.auth_method;
    if (am === AUTH_METHOD_CRAM_CERT && connection.notes.auth_ticket) {
        return plugin.auth_cram_cert(next, connection, params);
    }
    return next();
};

exports.check_cram_cert_passwd = function (connection, credentials, cb) {
    var data = JSON.parse(credentials);
    var auth_str = connection.notes.auth_ticket+data['pub_key'];

    // connection.loginfo(this, "auth_str :"+auth_str);
    // connection.loginfo(this, "credentials :"+credentials);
    var tt= data['signature'];
    for(var i = 0; i < tt.length;i++){
        var verifier = crypto.createVerify ('SHA1');
        verifier.update (auth_str);
        var success = verifier.verify (tt[i][0], tt[i][1],'base64');
        if(!success){
            connection.loginfo(this, "invalid signature"+i);
            return cb(false);
        } 
    }
    connection.notes.pub_key = data['pub_key'];
    connection.notes.authenticated = true;
    return cb(true);

};

exports.check_user = function (next, connection, credentials, method) {
    var plugin = this;
    connection.notes.authenticating = false;
    // if (!(credentials[0] && credentials[1])) {
    //     connection.respond(504, "Invalid AUTH string", function () {
    //         connection.reset_transaction(function () {
    //             return next(OK);
    //         });
    //     });
    //     return;
    // }

    var passwd_ok = function (valid) {
        if (valid) {
            connection.relaying = 1;
            connection.results.add({name:'relay'}, {pass: 'auth'});
            connection.respond(235, "Authentication successful", function () {
                connection.authheader = "(authenticated bits=0)\n";
                connection.auth_results('auth=pass ('+method.toLowerCase()+')' );
                connection.notes.auth_user = credentials[0];
                connection.notes.auth_passwd = credentials[1];
                return next(OK);
            });
            return;
        }

        if (!connection.notes.auth_fails) {
            connection.notes.auth_fails = 0;
        }
        connection.notes.auth_fails++;

        connection.notes.auth_login_userlogin = null;
        connection.notes.auth_login_asked_login = false;

        var delay = Math.pow(2, connection.notes.auth_fails - 1);
        if (plugin.timeout && delay >= plugin.timeout) { delay = plugin.timeout - 1; }
        connection.lognotice(plugin, 'delaying response for ' + delay + ' seconds');
        // here we include the username, as shown in RFC 5451 example
        connection.auth_results('auth=fail ('+method.toLowerCase()+') smtp.auth='+ credentials[0]);
        setTimeout(function () {
            connection.respond(535, "Authentication failed", function () {
                connection.reset_transaction(function () {
                    return next(OK);
                });
            });
        }, delay * 1000);
    };

    if (method === AUTH_METHOD_CRAM_CERT) {
        plugin.check_cram_cert_passwd(connection, credentials, passwd_ok);
    }
};

exports.select_auth_method = function(next, connection, method) {
    var split = method.split(/\s+/);
    method = split.shift().toUpperCase();
    if (!connection.notes.allowed_auth_methods) return next();
    if (connection.notes.allowed_auth_methods.indexOf(method) === -1) return next();

    connection.notes.authenticating = true;
    connection.notes.auth_method = method;

    if (method === AUTH_METHOD_CRAM_CERT) {
        return this.auth_cram_cert(next, connection);
    }
};

exports.auth_cram_cert = function(next, connection, params) {
    var plugin = this;
    if (params) {
        var credentials = utils.unbase64(params[0]);
        return plugin.check_user(next, connection, credentials, AUTH_METHOD_CRAM_CERT);
    }
    
    var ticket = '<' + plugin.hexi(Math.floor(Math.random() * 1000000)) + '.' +
                plugin.hexi(Date.now()) + '@' + plugin.config.get('me') + '>';

    connection.loginfo(plugin, "ticket: " + ticket);
    connection.respond(334, utils.base64(ticket), function () {
        connection.notes.auth_ticket = ticket;
        return next(OK);
    });
};

exports.hexi = function (number) {
    return String(Math.abs(parseInt(number)).toString(16));
};
