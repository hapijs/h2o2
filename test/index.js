'use strict';
// Load modules

const Fs = require('fs');
const Http = require('http');
const Net = require('net');
const Zlib = require('zlib');
const Boom = require('boom');
const Code = require('code');
const H2o2 = require('..');
const Hapi = require('hapi');
const Hoek = require('hoek');
const Lab = require('lab');
const Wreck = require('wreck');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;

describe('H2o2', () => {

    const tlsOptions = {
        key: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA3IDFzxorKO8xWeCOosuK1pCPoTUMlhOkis4pWO9CLCv0o0Q7\nyUCZlHzPYWM49+QmWe5u3Xbl1rhkFsoeYowH1bts5r6HY8xYHexvU+6zEyxOU4Q7\nP7EXkFfW5h7WsO6uaEyEBVdniTIjK4c8hzjy7h6hNIvM+kEAAy1UFatMKmOwsp4Z\ns4+oCmS4ZPlItAMbRv/4a5DCopluOS7WN8UwwJ6zRrY8ZVFnkKPThflnwiaIy2Qh\nGgTwLANIUlWPQMh+LLHnV56NOlj1VUO03G+pKxTJ6ZkfYefaD41Ez4iPc7nyg4iD\njqnqFX+jYOLRoCktztYd9T43Sgb2sfgrlY0ENwIDAQABAoIBAQCoznyg/CumfteN\nMvh/cMutT6Zlh7NHAWqqSQImb6R9JHl4tDgA7k+k+ZfZuphWTnd9yadeLDPwmeEm\nAT4Zu5IT8hSA4cPMhxe+cM8ZtlepifW8wjKJpA2iF10RdvJtKYyjlFBNtogw5A1A\nuZuA+fwgh5pqG8ykmTZlOEJzBFye5Z7xKc/gwy9BGv3RLNVf+yaJCqPKLltkAxtu\nFmrBLuIZMoOJvT+btgVxHb/nRVzURKv5iKMY6t3JM84OSxNn0/tHpX2xTcqsVre+\nsdSokKGYoyzk/9miDYhoSVOrM3bU5/ygBDt1Pmf/iyK/MDO2P9tX9cEp/+enJc7a\nLg5O/XCBAoGBAPNwayF6DLu0PKErsdCG5dwGrxhC69+NBEJkVDMPMjSHXAQWneuy\n70H+t2QHxpDbi5wMze0ZClMlgs1wItm4/6iuvOn9HJczwiIG5yM9ZJo+OFIqlBq3\n1vQG+oEXe5VpTfpyQihxqTSiMuCXkTYtNjneHseXWAjFuUQe9AOxxzNRAoGBAOfh\nZEEDY7I1Ppuz7bG1D6lmzYOTZZFfMCVGGTrYmam02+rS8NC+MT0wRFCblQ0E7SzM\nr9Bv2vbjrLY5fCe/yscF+/u/UHJu1dR7j62htdYeSi7XbQiSwyUm1QkMXjKDQPUw\njwR3WO8ZHQf2tywE+7iRs/bJ++Oolaw03HoIp40HAoGBAJJwGpGduJElH5+YCDO3\nIghUIPnIL9lfG6PQdHHufzXoAusWq9J/5brePXU31DOJTZcGgM1SVcqkcuWfwecU\niP3wdwWOU6eE5A/R9TJWmPDL4tdSc5sK4YwTspb7CEVdfiHcn31yueVGeLJvmlNr\nqQXwXrWTjcphHkwjDog2ZeyxAoGBAJ5Yyq+i8uf1eEW3v3AFZyaVr25Ur51wVV5+\n2ifXVkgP28YmOpEx8EoKtfwd4tE7NgPL25wJZowGuiDObLxwOrdinMszwGoEyj0K\nC/nUXmpT0PDf5/Nc1ap/NCezrHfuLePCP0gbgD329l5D2p5S4NsPlMfI8xxqOZuZ\nlZ44XsLtAoGADiM3cnCZ6x6/e5UQGfXa6xN7KoAkjjyO+0gu2AF0U0jDFemu1BNQ\nCRpe9zVX9AJ9XEefNUGfOI4bhRR60RTJ0lB5Aeu1xAT/OId0VTu1wRrbcnwMHGOo\nf7Kk1Vk5+1T7f1QbTu/q4ddp22PEt2oGJ7widRTZrr/gtH2wYUEjMVQ=\n-----END RSA PRIVATE KEY-----\n',
        cert: '-----BEGIN CERTIFICATE-----\nMIIC+zCCAeOgAwIBAgIJANnDRcmEqJssMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNV\nBAMMCWxvY2FsaG9zdDAeFw0xNzA5MTIyMjMxMDRaFw0yNzA5MTAyMjMxMDRaMBQx\nEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\nggEBANyAxc8aKyjvMVngjqLLitaQj6E1DJYTpIrOKVjvQiwr9KNEO8lAmZR8z2Fj\nOPfkJlnubt125da4ZBbKHmKMB9W7bOa+h2PMWB3sb1PusxMsTlOEOz+xF5BX1uYe\n1rDurmhMhAVXZ4kyIyuHPIc48u4eoTSLzPpBAAMtVBWrTCpjsLKeGbOPqApkuGT5\nSLQDG0b/+GuQwqKZbjku1jfFMMCes0a2PGVRZ5Cj04X5Z8ImiMtkIRoE8CwDSFJV\nj0DIfiyx51eejTpY9VVDtNxvqSsUyemZH2Hn2g+NRM+Ij3O58oOIg46p6hV/o2Di\n0aApLc7WHfU+N0oG9rH4K5WNBDcCAwEAAaNQME4wHQYDVR0OBBYEFJBSho+nF530\nsxpoBxYqD/ynn/t0MB8GA1UdIwQYMBaAFJBSho+nF530sxpoBxYqD/ynn/t0MAwG\nA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAJFAh3X5CYFAl0cI6Q7Vcp4H\nO0S8s/C4FHNIsyUu54NcRH3taUwn3Fshn5LiwaEdFmouALbxMaejvEVw7hVBtY9X\nOjqt0mZ6+X6GOFhoUvlaG1c7YLOk5x51TXchg8YD2wxNXS0rOrAdZaScOsy8Q62S\nHehBJMN19JK8TiR3XXzxKVNcFcg0wyQvCGgjrHReaUF8WePfWHtZDdP01kBmMEIo\n6wY7E3jFqvDUs33vTOB5kmWixIoJKmkgOVmbgchmu7z27n3J+fawNr2r4IwjdUpK\nc1KvFYBXLiT+2UVkOJbBZ3C8mKfhXKHs2CrI3cSa4+E0sxTy4joG/yzlRs5l954=\n-----END CERTIFICATE-----\n'
    };

    const provisionServer = function (options) {

        const server = new Hapi.Server();
        server.connection(options);
        server.register(H2o2, Hoek.ignore);
        return server;
    };

    it('overrides maxSockets', { parallel: false }, (done) => {

        const orig = Wreck.request;
        Wreck.request = function (method, uri, options, callback) {

            Wreck.request = orig;
            expect(options.agent.maxSockets).to.equal(213);
            done();
        };

        const server = provisionServer();
        server.route({ method: 'GET', path: '/', handler: { proxy: { host: 'localhost', maxSockets: 213 } } });
        server.inject('/', (res) => { });
    });

    it('uses node default with maxSockets set to false', { parallel: false }, (done) => {

        const orig = Wreck.request;
        Wreck.request = function (method, uri, options, callback) {

            Wreck.request = orig;
            expect(options.agent).to.equal(undefined);
            done();
        };

        const server = provisionServer();
        server.route({ method: 'GET', path: '/', handler: { proxy: { host: 'localhost', maxSockets: false } } });
        server.inject('/', (res) => { });
    });

    it('forwards on the response when making a GET request', (done) => {

        const profile = function (request, reply) {

            reply({ id: 'fa0dbda9b1b', name: 'John Doe' }).state('test', '123');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/profile', handler: profile, config: { cache: { expiresIn: 2000 } } });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/profile', handler: { proxy: { host: 'localhost', port: upstream.info.port, xforward: true, passThrough: true } } });
            server.state('auto', { autoValue: 'xyz' });

            server.inject('/profile', (response) => {

                expect(response.statusCode).to.equal(200);
                expect(response.payload).to.contain('John Doe');
                expect(response.headers['set-cookie'][0]).to.include(['test=123']);
                expect(response.headers['set-cookie'][1]).to.include(['auto=xyz']);
                expect(response.headers['cache-control']).to.equal('max-age=2, must-revalidate, private');

                server.inject('/profile', (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.payload).to.contain('John Doe');
                    done();
                });
            });
        });
    });

    it('throws when used with explicit route payload config other than data or steam', (done) => {

        const server = provisionServer();
        expect(() => {

            server.route({
                method: 'POST',
                path: '/',
                config: {
                    handler: {
                        proxy: { host: 'example.com' }
                    },
                    payload: {
                        output: 'file'
                    }
                }
            });
        }).to.throw('Cannot proxy if payload is parsed or if output is not stream or data');
        done();
    });

    it('throws when setup with invalid options', (done) => {

        const server = provisionServer();
        expect(() => {

            server.route({
                method: 'POST',
                path: '/',
                config: {
                    handler: {
                        proxy: { some: 'key' }
                    }
                }
            });
        }).to.throw(/\"value\" must contain at least one of \[host, mapUri, uri\]/);
        done();
    });

    it('throws when used with explicit route payload parse config set to false', (done) => {

        const server = provisionServer();
        expect(() => {

            server.route({
                method: 'POST',
                path: '/',
                config: {
                    handler: {
                        proxy: { host: 'example.com' }
                    },
                    payload: {
                        parse: true
                    }
                }
            });
        }).to.throw('Cannot proxy if payload is parsed or if output is not stream or data');
        done();
    });

    it('allows when used with explicit route payload output data config', (done) => {

        const server = provisionServer();
        expect(() => {

            server.route({
                method: 'POST',
                path: '/',
                config: {
                    handler: {
                        proxy: { host: 'example.com' }
                    },
                    payload: {
                        output: 'data'
                    }
                }
            });
        }).to.not.throw();
        done();
    });

    it('uses protocol without ":"', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { proxy: { host: 'localhost', port: upstream.info.port, protocol: 'http' } } });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('ok');
                done();
            });
        });
    });

    it('forwards upstream headers', (done) => {

        const headers = function (request, reply) {

            reply({ status: 'success' })
                .header('Custom1', 'custom header value 1')
                .header('X-Custom2', 'custom header value 2');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/headers', handler: headers });
        upstream.start(() => {

            const server = provisionServer({ routes: { cors: true } });
            server.route({ method: 'GET', path: '/headers', handler: { proxy: { host: 'localhost', port: upstream.info.port, passThrough: true } } });

            server.inject('/headers', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('{\"status\":\"success\"}');
                expect(res.headers.custom1).to.equal('custom header value 1');
                expect(res.headers['x-custom2']).to.equal('custom header value 2');
                done();
            });
        });
    });

    // it('overrides upstream cors headers', (done) => {
    //
    //     const headers = function (request, reply) {
    //
    //         reply().header('access-control-allow-headers', 'Invalid, List, Of, Values');
    //     };
    //
    //     const upstream = new Hapi.Server();
    //     upstream.connection();
    //     upstream.route({ method: 'GET', path: '/', handler: headers });
    //     upstream.start(function () {
    //
    //         const server = provisionServer({ routes: { cors: { credentials: true } } });
    //         server.route({ method: 'GET', path: '/', handler: { proxy: { host: 'localhost', port: upstream.info.port, passThrough: true } } });
    //
    //         server.inject('/', (res) => {
    //
    //             expect(res.headers['access-control-allow-headers']).to.equal('Invalid, List, Of, Values');
    //             done();
    //         });
    //     });
    // });

    it('merges upstream headers', (done) => {

        const headers = function (request, reply) {

            reply({ status: 'success' })
                .vary('X-Custom3');
        };

        const onResponse = function (err, res, request, reply, settings, ttl) {

            expect(err).to.be.null();
            reply(res).vary('Something');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/headers', handler: headers });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/headers', handler: { proxy: { host: 'localhost', port: upstream.info.port, passThrough: true, onResponse } } });

            server.inject({ url: '/headers', headers: { 'accept-encoding': 'gzip' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.headers.vary).to.equal('X-Custom3,accept-encoding,Something');
                done();
            });
        });
    });

    it('forwards gzipped content', (done) => {

        const gzipHandler = function (request, reply) {

            reply('123456789012345678901234567890123456789012345678901234567890');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/gzip', handler: gzipHandler });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/gzip', handler: { proxy: { host: 'localhost', port: upstream.info.port, passThrough: true } } });

            Zlib.gzip(new Buffer('123456789012345678901234567890123456789012345678901234567890'), (err, zipped) => {

                expect(err).to.not.exist();

                server.inject({ url: '/gzip', headers: { 'accept-encoding': 'gzip' } }, (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.rawPayload).to.equal(zipped);
                    done();
                });
            });
        });
    });

    it('forwards gzipped stream', (done) => {

        const gzipStreamHandler = function (request, reply) {

            reply.file(__dirname + '/../package.json');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.register(require('inert'), Hoek.ignore);
        upstream.route({ method: 'GET', path: '/gzipstream', handler: gzipStreamHandler });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/gzipstream', handler: { proxy: { host: 'localhost', port: upstream.info.port, passThrough: true } } });

            server.inject({ url: '/gzipstream', headers: { 'accept-encoding': 'gzip' } }, (res) => {

                expect(res.statusCode).to.equal(200);

                Fs.readFile(__dirname + '/../package.json', { encoding: 'utf8' }, (err, file) => {

                    expect(err).to.be.null();
                    Zlib.unzip(res.rawPayload, (err, unzipped) => {

                        expect(err).to.not.exist();
                        expect(unzipped.toString('utf8')).to.equal(file);
                        done();
                    });
                });
            });
        });
    });

    it('does not forward upstream headers without passThrough', (done) => {

        const headers = function (request, reply) {

            reply({ status: 'success' })
                .header('Custom1', 'custom header value 1')
                .header('X-Custom2', 'custom header value 2')
                .header('access-control-allow-headers', 'Invalid, List, Of, Values');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/noHeaders', handler: headers });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/noHeaders', handler: { proxy: { host: 'localhost', port: upstream.info.port } } });

            server.inject('/noHeaders', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('{\"status\":\"success\"}');
                expect(res.headers.custom1).to.not.exist();
                expect(res.headers['x-custom2']).to.not.exist();
                done();
            });
        });
    });

    it('request a cached proxy route', (done) => {

        let activeCount = 0;
        const activeItem = function (request, reply) {

            reply({
                id: '55cf687663',
                name: 'Active Items',
                count: activeCount++
            });
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/item', handler: activeItem });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/item', handler: { proxy: { host: 'localhost', port: upstream.info.port, protocol: 'http:' } }, config: { cache: { expiresIn: 500 } } });

            server.inject('/item', (response) => {

                expect(response.statusCode).to.equal(200);
                expect(response.payload).to.contain('Active Items');
                const counter = response.result.count;

                server.inject('/item', (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result.count).to.equal(counter);
                    done();
                });
            });
        });
    });

    it('forwards on the status code when making a POST request', (done) => {

        const item = function (request, reply) {

            reply({ id: '55cf687663', name: 'Items' }).created('http://example.com');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'POST', path: '/item', handler: item });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'POST', path: '/item', handler: { proxy: { host: 'localhost', port: upstream.info.port } } });

            server.inject({ url: '/item', method: 'POST' }, (res) => {

                expect(res.statusCode).to.equal(201);
                expect(res.payload).to.contain('Items');
                done();
            });
        });
    });

    it('sends the correct status code when a request is unauthorized', (done) => {

        const unauthorized = function (request, reply) {

            reply(Boom.unauthorized('Not authorized'));
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/unauthorized', handler: unauthorized });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/unauthorized', handler: { proxy: { host: 'localhost', port: upstream.info.port } }, config: { cache: { expiresIn: 500 } } });

            server.inject('/unauthorized', (res) => {

                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('sends a 404 status code when a proxied route does not exist', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'POST', path: '/notfound', handler: { proxy: { host: 'localhost', port: upstream.info.port } } });

            server.inject('/notfound', (res) => {

                expect(res.statusCode).to.equal(404);
                done();
            });
        });
    });

    it('overrides status code when a custom onResponse returns an error', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const onResponseWithError = function (err, res, request, reply, settings, ttl) {

                expect(err).to.be.null();
                reply(Boom.forbidden('Forbidden'));
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/onResponseError', handler: { proxy: { host: 'localhost', port: upstream.info.port, onResponse: onResponseWithError } } });

            server.inject('/onResponseError', (res) => {

                expect(res.statusCode).to.equal(403);
                done();
            });
        });
    });

    it('adds cookie to response', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const on = function (err, res, request, reply, settings, ttl) {

                expect(err).to.be.null();
                reply(res).state('a', 'b');
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { proxy: { host: 'localhost', port: upstream.info.port, onResponse: on } } });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(404);
                expect(res.headers['set-cookie'][0]).to.equal('a=b; Secure; HttpOnly; SameSite=Strict');
                done();
            });
        });
    });

    it('calls onRequest when it\'s created', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            let called = false;
            const onRequestWithSocket = function (req) {

                called = true;
                expect(req).to.be.an.instanceof(Http.ClientRequest);
            };

            const on = function (err, res, request, reply, settings, ttl) {

                expect(err).to.be.null();
                reply(this.c);
            };

            const handler = {
                proxy: {
                    host: 'localhost',
                    port: upstream.info.port,
                    onRequest: onRequestWithSocket,
                    onResponse: on
                }
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/onRequestSocket', config: { handler, bind: { c: 6 } } });

            server.inject('/onRequestSocket', (res) => {

                expect(res.result).to.equal(6);
                expect(called).to.equal(true);
                done();
            });
        });
    });

    it('binds onResponse to route bind config', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const onResponseWithError = function (err, res, request, reply, settings, ttl) {

                expect(err).to.be.null();
                reply(this.c);
            };

            const handler = {
                proxy: {
                    host: 'localhost',
                    port: upstream.info.port,
                    onResponse: onResponseWithError
                }
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/onResponseError', config: { handler, bind: { c: 6 } } });

            server.inject('/onResponseError', (res) => {

                expect(res.result).to.equal(6);
                done();
            });
        });
    });

    it('binds onResponse to route bind config in plugin', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const plugin = function (server, options, next) {

                const onResponseWithError = function (err, res, request, reply, settings, ttl) {

                    expect(err).to.be.null();
                    reply(this.c);
                };

                const handler = {
                    proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        onResponse: onResponseWithError
                    }
                };

                server.route({ method: 'GET', path: '/', config: { handler, bind: { c: 6 } } });
                return next();
            };

            plugin.attributes = {
                name: 'test'
            };

            const server = provisionServer();

            server.register(plugin, (err) => {

                expect(err).to.not.exist();

                server.inject('/', (res) => {

                    expect(res.result).to.equal(6);
                    done();
                });
            });
        });
    });

    it('binds onResponse to plugin bind', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const plugin = function (server, options, next) {

                const onResponseWithError = function (err, res, request, reply, settings, ttl) {

                    expect(err).to.be.null();
                    reply(this.c);
                };

                const handler = {
                    proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        onResponse: onResponseWithError
                    }
                };

                server.bind({ c: 7 });
                server.route({ method: 'GET', path: '/', config: { handler } });
                return next();
            };

            plugin.attributes = {
                name: 'test'
            };

            const server = provisionServer();

            server.register(plugin, (err) => {

                expect(err).to.not.exist();

                server.inject('/', (res) => {

                    expect(res.result).to.equal(7);
                    done();
                });
            });
        });
    });

    it('binds onResponse to route bind config in plugin when plugin also has bind', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const plugin = function (server, options, next) {

                const onResponseWithError = function (err, res, request, reply, settings, ttl) {

                    expect(err).to.be.null();
                    reply(this.c);
                };

                const handler = {
                    proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        onResponse: onResponseWithError
                    }
                };

                server.bind({ c: 7 });
                server.route({ method: 'GET', path: '/', config: { handler, bind: { c: 4 } } });
                return next();
            };

            plugin.attributes = {
                name: 'test'
            };

            const server = provisionServer();

            server.register(plugin, (err) => {

                expect(err).to.not.exist();

                server.inject('/', (res) => {

                    expect(res.result).to.equal(4);
                    done();
                });
            });
        });
    });

    it('calls the onResponse function if the upstream is unreachable', (done) => {

        const dummy = new Hapi.Server();
        dummy.connection();
        dummy.start(() => {

            const dummyPort = dummy.info.port;
            dummy.stop(Hoek.ignore);

            const failureResponse = function (err, res, request, reply, settings, ttl) {

                reply(err);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/failureResponse', handler: { proxy: { host: 'localhost', port: dummyPort, onResponse: failureResponse } }, config: { cache: { expiresIn: 500 } } });

            server.inject('/failureResponse', (res) => {

                expect(res.statusCode).to.equal(502);
                done();
            });
        });
    });

    it('sets x-forwarded-* headers', (done) => {

        const handler = function (request, reply) {

            reply(request.raw.req.headers);
        };

        const host = '127.0.0.1';

        const upstream = new Hapi.Server();
        upstream.connection({
            host
        });
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer({
                host,
                tls: tlsOptions
            });

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    proxy: {
                        host: upstream.info.host,
                        port: upstream.info.port,
                        protocol: 'http',
                        xforward: true
                    }
                }
            });

            server.start(() => {

                const requestProtocol = 'https';

                Wreck.get(`${requestProtocol}://${server.info.host}:${server.info.port}/`, {
                    rejectUnauthorized: false
                }, (err, res, body) => {

                    expect(err).to.be.null();
                    expect(res.statusCode).to.equal(200);
                    const result = JSON.parse(body);

                    const expectedClientAddress = '127.0.0.1';
                    const expectedClientAddressAndPort = expectedClientAddress + ':' + server.info.port;
                    if (Net.isIPv6(server.listener.address().address)) {
                        expectedClientAddress = '::ffff:127.0.0.1';
                        expectedClientAddressAndPort = '[' + expectedClientAddress + ']:' + server.info.port;
                    }

                    expect(result['x-forwarded-for']).to.equal(expectedClientAddress);
                    expect(result['x-forwarded-port']).to.match(/\d+/);
                    expect(result['x-forwarded-proto']).to.equal(requestProtocol);
                    expect(result['x-forwarded-host']).to.equal(expectedClientAddressAndPort);

                    server.stop(Hoek.ignore);
                    upstream.stop(Hoek.ignore);
                    done();
                });
            });
        });
    });

    it('adds x-forwarded-* headers to existing', (done) => {

        const handler = function (request, reply) {

            reply(request.raw.req.headers);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const mapUri = function (request, callback) {

                const headers = {
                    'x-forwarded-for': 'testhost',
                    'x-forwarded-port': 1337,
                    'x-forwarded-proto': 'https',
                    'x-forwarded-host': 'example.com'
                };

                return callback(null, 'http://127.0.0.1:' + upstream.info.port + '/', headers);
            };

            const server = provisionServer({ host: '127.0.0.1' });
            server.route({ method: 'GET', path: '/', handler: { proxy: { mapUri, xforward: true } } });

            server.start(() => {

                Wreck.get('http://127.0.0.1:' + server.info.port + '/', (err, res, body) => {

                    expect(err).to.be.null();
                    expect(res.statusCode).to.equal(200);
                    const result = JSON.parse(body);

                    const expectedClientAddress = '127.0.0.1';
                    const expectedClientAddressAndPort = expectedClientAddress + ':' + server.info.port;
                    if (Net.isIPv6(server.listener.address().address)) {
                        expectedClientAddress = '::ffff:127.0.0.1';
                        expectedClientAddressAndPort = '[' + expectedClientAddress + ']:' + server.info.port;
                    }

                    expect(result['x-forwarded-for']).to.equal('testhost,' + expectedClientAddress);
                    expect(result['x-forwarded-port']).to.match(/1337\,\d+/);
                    expect(result['x-forwarded-proto']).to.equal('https,http');
                    expect(result['x-forwarded-host']).to.equal('example.com,' + expectedClientAddressAndPort);
                    server.stop(Hoek.ignore);
                    upstream.stop(Hoek.ignore);
                    done();
                });
            });
        });
    });

    it('does not clobber existing x-forwarded-* headers', (done) => {

        const handler = function (request, reply) {

            reply(request.raw.req.headers);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const mapUri = function (request, callback) {

                const headers = {
                    'x-forwarded-for': 'testhost',
                    'x-forwarded-port': 1337,
                    'x-forwarded-proto': 'https',
                    'x-forwarded-host': 'example.com'
                };

                return callback(null, 'http://127.0.0.1:' + upstream.info.port + '/', headers);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { proxy: { mapUri, xforward: true } } });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                const result = JSON.parse(res.payload);
                expect(result['x-forwarded-for']).to.equal('testhost');
                expect(result['x-forwarded-port']).to.equal('1337');
                expect(result['x-forwarded-proto']).to.equal('https');
                expect(result['x-forwarded-host']).to.equal('example.com');
                done();
            });
        });
    });

    it('forwards on a POST body', (done) => {

        const echoPostBody = function (request, reply) {

            reply(request.payload.echo + request.raw.req.headers['x-super-special']);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'POST', path: '/echo', handler: echoPostBody });
        upstream.start(() => {

            const mapUri = function (request, callback) {

                return callback(null, 'http://127.0.0.1:' + upstream.info.port + request.path + (request.url.search || ''), { 'x-super-special': '@' });
            };

            const server = provisionServer();
            server.route({ method: 'POST', path: '/echo', handler: { proxy: { mapUri } } });

            server.inject({ url: '/echo', method: 'POST', payload: '{"echo":true}' }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('true@');
                done();
            });
        });
    });

    it('replies with an error when it occurs in mapUri', (done) => {

        const mapUriWithError = function (request, callback) {

            return callback(new Error('myerror'));
        };

        const server = provisionServer();
        server.route({ method: 'GET', path: '/maperror', handler: { proxy: { mapUri: mapUriWithError } } });

        server.inject('/maperror', (res) => {

            expect(res.statusCode).to.equal(500);
            done();
        });
    });

    it('maxs out redirects to same endpoint', (done) => {

        const redirectHandler = function (request, reply) {

            reply.redirect('/redirect?x=1');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/redirect', handler: redirectHandler });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/redirect', handler: { proxy: { host: 'localhost', port: upstream.info.port, passThrough: true, redirects: 2 } } });

            server.inject('/redirect?x=1', (res) => {

                expect(res.statusCode).to.equal(502);
                done();
            });
        });
    });

    it('errors on redirect missing location header', (done) => {

        const redirectHandler = function (request, reply) {

            reply().code(302);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/redirect', handler: redirectHandler });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/redirect', handler: { proxy: { host: 'localhost', port: upstream.info.port, passThrough: true, redirects: 2 } } });

            server.inject('/redirect?x=3', (res) => {

                expect(res.statusCode).to.equal(502);
                done();
            });
        });
    });

    it('errors on redirection to bad host', (done) => {

        const server = provisionServer();
        server.route({ method: 'GET', path: '/nowhere', handler: { proxy: { host: 'no.such.domain.x8' } } });

        server.inject('/nowhere', (res) => {

            expect(res.statusCode).to.equal(502);
            done();
        });
    });

    it('errors on redirection to bad host (https)', (done) => {

        const server = provisionServer();
        server.route({ method: 'GET', path: '/nowhere', handler: { proxy: { host: 'no.such.domain.x8', protocol: 'https' } } });

        server.inject('/nowhere', (res) => {

            expect(res.statusCode).to.equal(502);
            done();
        });
    });

    it('redirects to another endpoint', (done) => {

        const redirectHandler = function (request, reply) {

            reply.redirect('/profile');
        };

        const profile = function (request, reply) {

            reply({ id: 'fa0dbda9b1b', name: 'John Doe' }).state('test', '123');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/redirect', handler: redirectHandler });
        upstream.route({ method: 'GET', path: '/profile', handler: profile, config: { cache: { expiresIn: 2000 } } });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/redirect', handler: { proxy: { host: 'localhost', port: upstream.info.port, passThrough: true, redirects: 2 } } });
            server.state('auto', { autoValue: 'xyz' });

            server.inject('/redirect', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.contain('John Doe');
                expect(res.headers['set-cookie'][0]).to.include(['test=123']);
                expect(res.headers['set-cookie'][1]).to.include(['auto=xyz']);
                done();
            });
        });
    });

    it('redirects to another endpoint with relative location', (done) => {

        const redirectHandler = function (request, reply) {

            reply().header('Location', '//localhost:' + request.server.info.port + '/profile').code(302);
        };

        const profile = function (request, reply) {

            reply({ id: 'fa0dbda9b1b', name: 'John Doe' }).state('test', '123');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/redirect', handler: redirectHandler });
        upstream.route({ method: 'GET', path: '/profile', handler: profile, config: { cache: { expiresIn: 2000 } } });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/redirect', handler: { proxy: { host: 'localhost', port: upstream.info.port, passThrough: true, redirects: 2 } } });
            server.state('auto', { autoValue: 'xyz' });

            server.inject('/redirect?x=2', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.contain('John Doe');
                expect(res.headers['set-cookie'][0]).to.include(['test=123']);
                expect(res.headers['set-cookie'][1]).to.include(['auto=xyz']);
                done();
            });
        });
    });

    it('redirects to a post endpoint with stream', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'POST',
            path: '/post1',
            handler: function (request, reply) {

                return reply.redirect('/post2').rewritable(false);
            }
        });

        upstream.route({
            method: 'POST',
            path: '/post2',
            handler: function (request, reply) {

                return reply(request.payload);
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'POST', path: '/post1', handler: { proxy: { host: 'localhost', port: upstream.info.port, redirects: 3 } }, config: { payload: { output: 'stream' } } });

            server.inject({ method: 'POST', url: '/post1', payload: 'test', headers: { 'content-type': 'text/plain' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('test');
                done();
            });
        });
    });

    it('errors when proxied request times out', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/timeout1',
            handler: function (request, reply) {

                setTimeout(() => {

                    return reply('Ok');
                }, 10);
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/timeout1', handler: { proxy: { host: 'localhost', port: upstream.info.port, timeout: 5 } } });

            server.inject('/timeout1', (res) => {

                expect(res.statusCode).to.equal(504);
                done();
            });
        });
    });

    it('uses default timeout when nothing is set', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({

            method: 'GET',
            path: '/timeout2',
            handler: function (request, reply) {

                setTimeout(() => {

                    return reply('Ok');
                }, 10);
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/timeout2', handler: { proxy: { host: 'localhost', port: upstream.info.port } } });

            server.inject('/timeout2', (res) => {

                expect(res.statusCode).to.equal(200);
                done();
            });
        });
    });

    it('uses rejectUnauthorized to allow proxy to self signed ssl server', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection({ tls: tlsOptions });
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('Ok');
            }
        });

        upstream.start(() => {

            const mapSslUri = function (request, callback) {

                return callback(null, 'https://127.0.0.1:' + upstream.info.port);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/allow', handler: { proxy: { mapUri: mapSslUri, rejectUnauthorized: false } } });
            server.inject('/allow', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('Ok');
                done();
            });
        });
    });

    it('uses rejectUnauthorized to not allow proxy to self signed ssl server', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection({ tls: tlsOptions });
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('Ok');
            }
        });

        upstream.start(() => {

            const mapSslUri = function (request, callback) {

                return callback(null, 'https://127.0.0.1:' + upstream.info.port);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/reject', handler: { proxy: { mapUri: mapSslUri, rejectUnauthorized: true } } });
            server.inject('/reject', (res) => {

                expect(res.statusCode).to.equal(502);
                done();
            });
        });
    });

    it('the default rejectUnauthorized should not allow proxied server cert to be self signed', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection({ tls: tlsOptions });
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('Ok');
            }
        });

        upstream.start(() => {

            const mapSslUri = function (request, callback) {

                return callback(null, 'https://127.0.0.1:' + upstream.info.port);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/sslDefault', handler: { proxy: { mapUri: mapSslUri } } });
            server.inject('/sslDefault', (res) => {

                expect(res.statusCode).to.equal(502);
                done();
            });
        });
    });

    it('times out when proxy timeout is less than server', { parallel: false }, (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/timeout2',
            handler: function (request, reply) {

                setTimeout(() => {

                    return reply('Ok');
                }, 10);
            }
        });

        upstream.start(() => {

            const server = provisionServer({ routes: { timeout: { server: 8 } } });
            server.route({ method: 'GET', path: '/timeout2', handler: { proxy: { host: 'localhost', port: upstream.info.port, timeout: 2 } } });
            server.inject('/timeout2', (res) => {

                expect(res.statusCode).to.equal(504);
                done();
            });
        });
    });

    it('times out when server timeout is less than proxy', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/timeout1',
            handler: function (request, reply) {

                setTimeout(() => {

                    return reply('Ok');
                }, 10);
            }
        });

        upstream.start(() => {

            const server = provisionServer({ routes: { timeout: { server: 5 } } });
            server.route({ method: 'GET', path: '/timeout1', handler: { proxy: { host: 'localhost', port: upstream.info.port, timeout: 15 } } });
            server.inject('/timeout1', (res) => {

                expect(res.statusCode).to.equal(503);
                done();
            });
        });
    });

    it('proxies via uri template', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/item',
            handler: function (request, reply) {

                return reply({ a: 1 });
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/handlerTemplate', handler: { proxy: { uri: '{protocol}://localhost:' + upstream.info.port + '/item' } } });

            server.inject('/handlerTemplate', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.contain('"a":1');
                done();
            });
        });
    });

    it('proxies via uri template with request.param variables', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/item/{param_a}/{param_b}',
            handler: function (request, reply) {

                return reply({ a: request.params.param_a, b: request.params.param_b });
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/handlerTemplate/{a}/{b}', handler: { proxy: { uri: 'http://localhost:' + upstream.info.port + '/item/{a}/{b}' } } });

            const prma = 'foo';
            const prmb = 'bar';
            server.inject(`/handlerTemplate/${prma}/${prmb}`, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.contain(`"a":"${prma}"`);
                expect(res.payload).to.contain(`"b":"${prmb}"`);
                done();
            });
        });
    });

    it('passes upstream caching headers', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/cachedItem',
            handler: function (request, reply) {

                return reply({ a: 1 });
            },
            config: {
                cache: {
                    expiresIn: 2000
                }
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/cachedItem', handler: { proxy: { host: 'localhost', port: upstream.info.port, ttl: 'upstream' } } });
            server.state('auto', { autoValue: 'xyz' });

            server.inject('/cachedItem', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['cache-control']).to.equal('max-age=2, must-revalidate, private');
                done();
            });
        });
    });

    it('ignores when no upstream caching headers to pass', (done) => {

        const upstream = Http.createServer((req, res) => {

            res.end('not much');
        });

        upstream.listen(0, () => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { proxy: { host: 'localhost', port: upstream.address().port, ttl: 'upstream' } } });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['cache-control']).to.equal('no-cache');
                done();
            });
        });
    });

    it('ignores when upstream caching header is invalid', (done) => {

        const upstream = Http.createServer((req, res) => {

            res.writeHeader(200, { 'cache-control': 'some crap that does not work' });
            res.end('not much');
        });

        upstream.listen(0, () => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { proxy: { host: 'localhost', port: upstream.address().port, ttl: 'upstream' } } });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['cache-control']).to.equal('no-cache');
                done();
            });
        });
    });

    it('overrides response code with 304', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/item',
            handler: function (request, reply) {

                return reply({ a: 1 });
            }
        });

        upstream.start(() => {

            const onResponse304 = function (err, res, request, reply, settings, ttl) {

                expect(err).to.be.null();
                return reply(res).code(304);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/304', handler: { proxy: { uri: 'http://localhost:' + upstream.info.port + '/item', onResponse: onResponse304 } } });

            server.inject('/304', (res) => {

                expect(res.statusCode).to.equal(304);
                expect(res.payload).to.equal('');
                done();
            });
        });
    });

    it('cleans up when proxy response replaced in onPreResponse', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/item',
            handler: function (request, reply) {

                return reply({ a: 1 });
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.ext('onPreResponse', (request, reply) => {

                return reply({ something: 'else' });
            });

            server.route({ method: 'GET', path: '/item', handler: { proxy: { host: 'localhost', port: upstream.info.port } } });

            server.inject('/item', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result.something).to.equal('else');
                done();
            });
        });
    });

    it('retails accept-encoding header', (done) => {

        const profile = function (request, reply) {

            reply(request.headers['accept-encoding']);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler: profile, config: { cache: { expiresIn: 2000 } } });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { proxy: { host: 'localhost', port: upstream.info.port, acceptEncoding: true, passThrough: true } } });

            server.inject({ url: '/', headers: { 'accept-encoding': '*/*' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('*/*');
                done();
            });
        });
    });

    it('removes accept-encoding header', (done) => {

        const profile = function (request, reply) {

            reply(request.headers['accept-encoding']);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler: profile, config: { cache: { expiresIn: 2000 } } });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { proxy: { host: 'localhost', port: upstream.info.port, acceptEncoding: false, passThrough: true } } });

            server.inject({ url: '/', headers: { 'accept-encoding': '*/*' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('');
                done();
            });
        });
    });

    it('does not send multiple Content-Type headers on passthrough', { parallel: false }, (done) => {

        const server = provisionServer();

        const requestFn = Wreck.request;
        Wreck.request = function (method, url, options, cb) {

            Wreck.request = requestFn;
            expect(options.headers['content-type']).to.equal('application/json');
            expect(options.headers['Content-Type']).to.not.exist();
            cb(new Error('placeholder'));
        };
        server.route({ method: 'GET', path: '/test', handler: { proxy: { uri: 'http://localhost', passThrough: true } } });
        server.inject({ method: 'GET', url: '/test', headers: { 'Content-Type': 'application/json' } }, (res) => {

            done();
        });
    });

    it('allows passing in an agent through to Wreck', { parallel: false }, (done) => {

        const server = provisionServer();
        const agent = { name: 'myagent' };

        const requestFn = Wreck.request;
        Wreck.request = function (method, url, options, cb) {

            Wreck.request = requestFn;
            expect(options.agent).to.equal(agent);
            done();

        };
        server.route({ method: 'GET', path: '/agenttest', handler: { proxy: { uri: 'http://localhost', agent } } });
        server.inject({ method: 'GET', url: '/agenttest', headers: {} }, (res) => { });
    });

    it('excludes request cookies defined locally', (done) => {

        const handler = function (request, reply) {

            reply(request.state);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer();
            server.state('a');

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        passThrough: true
                    }
                }
            });

            server.inject({ url: '/', headers: { cookie: 'a=1;b=2' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                const cookies = JSON.parse(res.payload);
                expect(cookies).to.equal({ b: '2' });
                done();
            });
        });
    });

    it('includes request cookies defined locally (route level)', (done) => {

        const handler = function (request, reply) {

            return reply(request.state);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer();
            server.state('a', { passThrough: true });

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        passThrough: true,
                        localStatePassThrough: true
                    }
                }
            });

            server.inject({ url: '/', headers: { cookie: 'a=1;b=2' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                const cookies = JSON.parse(res.payload);
                expect(cookies).to.equal({ a: '1', b: '2' });
                done();
            });
        });
    });

    it('includes request cookies defined locally (cookie level)', (done) => {

        const handler = function (request, reply) {

            reply(request.state);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer();
            server.state('a', { passThrough: true });

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        passThrough: true
                    }
                }
            });

            server.inject({ url: '/', headers: { cookie: 'a=1;b=2' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                const cookies = JSON.parse(res.payload);
                expect(cookies).to.equal({ a: '1', b: '2' });
                done();
            });
        });
    });

    it('errors on invalid cookie header', (done) => {

        const server = provisionServer({ routes: { state: { failAction: 'ignore' } } });
        server.state('a', { passThrough: true });

        server.route({
            method: 'GET',
            path: '/',
            handler: {
                proxy: {
                    host: 'localhost',
                    port: 8080,
                    passThrough: true
                }
            }
        });

        server.inject({ url: '/', headers: { cookie: 'a' } }, (res) => {

            expect(res.statusCode).to.equal(400);
            done();
        });
    });

    it('drops cookies when all defined locally', (done) => {

        const handler = function (request, reply) {

            reply(request.state);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer();
            server.state('a');

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        passThrough: true
                    }
                }
            });

            server.inject({ url: '/', headers: { cookie: 'a=1' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                const cookies = JSON.parse(res.payload);
                expect(cookies).to.equal({});
                done();
            });
        });
    });

    it('excludes request cookies defined locally (state override)', (done) => {

        const handler = function (request, reply) {

            return reply(request.state);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer();
            server.state('a', { passThrough: false });

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        passThrough: true
                    }
                }
            });

            server.inject({ url: '/', headers: { cookie: 'a=1;b=2' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                const cookies = JSON.parse(res.payload);
                expect(cookies).to.equal({ b: '2' });
                done();
            });
        });
    });

    it('uses reply decorator', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            }
        });
        upstream.start(() => {

            const server = provisionServer();
            server.route({
                method: 'GET',
                path: '/',
                handler: function (request, reply) {

                    return reply.proxy({ host: 'localhost', port: upstream.info.port, xforward: true, passThrough: true });
                }
            });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('ok');
                done();
            });
        });
    });

    it('uses custom TLS settings', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection({ tls: tlsOptions });
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            }
        });

        upstream.start(() => {

            const server = new Hapi.Server();
            server.connection({});
            server.register({ register: H2o2.register, options: { secureProtocol: 'TLSv1_2_method', ciphers: 'ECDHE-RSA-AES128-SHA256' } });

            server.route({
                method: 'GET',
                path: '/',
                handler: function (request, reply) {

                    return reply.proxy({ host: '127.0.0.1', protocol: 'https', port: upstream.info.port, rejectUnauthorized: false });
                }
            });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('ok');
                done();
            });
        });
    });
});
