'use strict';
// Load modules

const Http = require('http');
const Https = require('https');
const Hoek = require('hoek');
const Joi = require('joi');
const Wreck = require('wreck');


// Declare internals

const internals = {
    agents: {}  // server.info.uri -> { http, https, insecure }
};


internals.defaults = {
    xforward: false,
    passThrough: false,
    redirects: false,
    timeout: 1000 * 60 * 3, // Timeout request after 3 minutes
    localStatePassThrough: false,   // Pass cookies defined by the server upstream
    maxSockets: Infinity
};


internals.schema = Joi.object({
    host: Joi.string(),
    port: Joi.number().integer(),
    protocol: Joi.string().valid('http', 'https', 'http:', 'https:'),
    uri: Joi.string(),
    passThrough: Joi.boolean(),
    localStatePassThrough: Joi.boolean(),
    acceptEncoding: Joi.boolean().when('passThrough', { is: true, otherwise: Joi.forbidden() }),
    rejectUnauthorized: Joi.boolean(),
    xforward: Joi.boolean(),
    redirects: Joi.number().min(0).integer().allow(false),
    timeout: Joi.number().integer(),
    mapUri: Joi.func(),
    onResponse: Joi.func(),
    onRequest: Joi.func(),
    agent: Joi.object(),
    ttl: Joi.string().valid('upstream').allow(null),
    maxSockets: Joi.number().positive().allow(false),
    secureProtocol: Joi.string(),
    ciphers: Joi.string()
})
    .xor('host', 'mapUri', 'uri')
    .without('mapUri', 'port')
    .without('mapUri', 'protocol')
    .without('uri', 'port')
    .without('uri', 'protocol');


exports.register = function (server, pluginOptions) {

    internals.defaults = Hoek.applyToDefaults(internals.defaults, pluginOptions);

    server.decorate('handler', 'proxy', internals.handler);

    server.decorate('toolkit', 'proxy', function (options) {

        return internals.handler(this.request.route, options)(this.request, this);
    });
};

exports.pkg = require('../package.json');


internals.handler = function (route, handlerOptions) {

    const settings = Hoek.applyToDefaultsWithShallow(internals.defaults, handlerOptions, ['agent']);
    Joi.assert(handlerOptions, internals.schema, 'Invalid proxy handler options (' + route.path + ')');
    Hoek.assert(!route.settings.payload || ((route.settings.payload.output === 'data' || route.settings.payload.output === 'stream') && !route.settings.payload.parse), 'Cannot proxy if payload is parsed or if output is not stream or data');
    settings.mapUri = handlerOptions.mapUri || internals.mapUri(handlerOptions.protocol, handlerOptions.host, handlerOptions.port, handlerOptions.uri);

    if (settings.ttl === 'upstream') {
        settings._upstreamTtl = true;
    }

    return async function (request, h) {

        const { uri, headers } = await settings.mapUri(request);

        const protocol = uri.split(':', 1)[0];

        const options = {
            headers: {},
            payload: request.payload,
            redirects: settings.redirects,
            timeout: settings.timeout,
            agent: internals.agent(protocol, settings, request)
        };

        const bind = request.route.settings.bind;

        if (settings.passThrough) {
            options.headers = Hoek.clone(request.headers);
            delete options.headers.host;

            if (settings.acceptEncoding === false) { // Defaults to true
                delete options.headers['accept-encoding'];
            }

            if (options.headers.cookie) {
                delete options.headers.cookie;

                const cookieHeader = request.server.states.passThrough(request.headers.cookie, settings.localStatePassThrough);
                if (cookieHeader) {
                    if (typeof cookieHeader !== 'string') {
                        throw cookieHeader; // Error
                    }

                    options.headers.cookie = cookieHeader;
                }
            }
        }

        if (headers) {
            Hoek.merge(options.headers, headers);
        }

        if (settings.xforward &&
            request.info.remotePort &&
            request.info.remoteAddress) {
            options.headers['x-forwarded-for'] = (options.headers['x-forwarded-for'] ? options.headers['x-forwarded-for'] + ',' : '') + request.info.remoteAddress;
            options.headers['x-forwarded-port'] = options.headers['x-forwarded-port'] || request.info.remotePort;
            options.headers['x-forwarded-proto'] = options.headers['x-forwarded-proto'] || request.server.info.protocol;
            options.headers['x-forwarded-host'] = options.headers['x-forwarded-host'] || request.info.host;
        }

        if (settings.ciphers) {
            options.ciphers = settings.ciphers;
        }

        if (settings.secureProtocol) {
            options.secureProtocol = settings.secureProtocol;
        }

        const contentType = request.headers['content-type'];
        if (contentType) {
            options.headers['content-type'] = contentType;
        }

        let ttl = null;
        let res;

        const promise = Wreck.request(request.method, uri, options);

        if (settings.onRequest) {
            settings.onRequest(promise.req);
        }

        try {
            res = await promise;
        }
        catch (error) {
            if (settings.onResponse) {
                return settings.onResponse.call(bind, error, res, request, h, settings, ttl);
            }

            throw error;
        }

        if (settings._upstreamTtl) {
            const cacheControlHeader = res.headers['cache-control'];
            if (cacheControlHeader) {
                const cacheControl = Wreck.parseCacheControl(cacheControlHeader);
                if (cacheControl) {
                    ttl = cacheControl['max-age'] * 1000;
                }
            }
        }

        if (settings.onResponse) {
            return settings.onResponse.call(bind, null, res, request, h, settings, ttl);
        }

        return h.response(res)
            .ttl(ttl)
            .code(res.statusCode)
            .passThrough(!!settings.passThrough);

    };
};


internals.handler.defaults = function (method) {

    const payload = method !== 'get' && method !== 'head';
    return payload ? {
        payload: {
            output: 'stream',
            parse: false
        }
    } : null;
};


internals.mapUri = function (protocol, host, port, uri) {

    if (uri) {
        return function (request) {

            if (uri.indexOf('{') === -1) {
                return { uri };
            }

            let address = uri.replace(/{protocol}/g, request.server.info.protocol)
                .replace(/{host}/g, request.server.info.host)
                .replace(/{port}/g, request.server.info.port)
                .replace(/{path}/g, request.url.path);

            Object.keys(request.params).forEach((key) => {

                const re = new RegExp(`{${key}}`,'g');
                address = address.replace(re,request.params[key]);
            });

            return {
                uri: address
            };
        };
    }

    if (protocol &&
        protocol[protocol.length - 1] !== ':') {

        protocol += ':';
    }

    protocol = protocol || 'http:';

    port = port || (protocol === 'http:' ? 80 : 443);
    const baseUrl = protocol + '//' + host + ':' + port;

    return function (request) {

        return {
            uri: (null, baseUrl + request.path + (request.url.search || ''))
        };
    };
};


internals.agent = function (protocol, settings, request) {

    if (settings.agent) {
        return settings.agent;
    }

    if (settings.maxSockets === false) {
        return undefined;
    }

    internals.agents[request.info.uri] = internals.agents[request.info.uri] || {};
    const agents = internals.agents[request.info.uri];

    const type = (protocol === 'http' ? 'http' : (settings.rejectUnauthorized === false ? 'insecure' : 'https'));
    if (!agents[type]) {
        agents[type] = (type === 'http' ? new Http.Agent() : (type === 'https' ? new Https.Agent() : new Https.Agent({ rejectUnauthorized: false })));
        agents[type].maxSockets = settings.maxSockets;
    }

    return agents[type];
};
