// Auth against a flat file
var net_utils = require('./net_utils');

exports.register = function () {
    var plugin = this;
    plugin.inherits('auth/auth_base');
    // var load_config = function () {
    //     plugin.cfg = plugin.config.get('auth_flat_file.ini', load_config);
    // };
    // load_config();
};

exports.hook_capabilities = function (next, connection) {
    // var plugin = this;
    // // don't allow AUTH unless private IP or encrypted
    // if (!net_utils.is_rfc1918(connection.remote_ip) && !connection.using_tls) {
    //     connection.logdebug(plugin, "Auth disabled for insecure public connection");
    //     return next();
    // }

    // var methods = null;
    // if (plugin.cfg.core && plugin.cfg.core.methods ) {
    //     methods = plugin.cfg.core.methods.split(',');
    // }
    // if (methods && methods.length > 0) {
    //     connection.capabilities.push('AUTH ' + methods.join(' '));
    //     connection.notes.allowed_auth_methods = methods;
    // }
    if (connection.using_tls) {
        var methods = [ 'LOGIN' ];
        connection.capabilities.push('AUTH ' + methods.join(' '));
        connection.notes.allowed_auth_methods = methods;
    }
    next();
};

exports.check_plain_passwd = function (connection, user, passwd, cb) {
    // Get LDAP config 
    var config = this.config.get('auth_ldap.ini');
    var ldap_url = 'ldap://127.0.0.1';
    if (config.core.server) {
        ldap_url = config.core.server;
    }
    var rejectUnauthorized = (config.core.rejectUnauthorized != undefined) ?
        config.core.rejectUnauthorized : true;

    var client = ldap.createClient({
        url: ldap_url,
        timeout: (config.core.timeout != undefined) ? config.core.timeout : 5000,
        tlsOptions: {
            rejectUnauthorized: rejectUnauthorized
        }
    });

    config.dns = Object.keys(config.dns).map(function (v) {
        return config.dns[v];
    })
    async.detectSeries(config.dns, function (dn, callback) {
        dn = dn.replace(/%u/g, user);
        client.bind(dn, passwd, function (err) {
            if (err) {
                connection.loginfo("auth_ldap: (" + dn + ") " + err.message);
                return callback(false);
            } else {
                client.unbind();
                return callback(true);
            }
        })
    }, function (result) {
        cb(result);
    });
}
// exports.get_plain_passwd = function (user, cb) {
//     var plugin = this;
//     if (plugin.cfg.users[user]) {
//         return cb(plugin.cfg.users[user]);
//     }
//     return cb();
// };
