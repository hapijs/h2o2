import { Server} from '@hapi/hapi';
import * as h2o2 from '..';
import { types } from '@hapi/lab'
import type { IncomingMessage } from 'http';
import type { Boom } from '@hapi/boom';
import type { Plugin, Request, ResponseObject, ResponseToolkit, ServerRoute } from '@hapi/hapi';
import type * as Wreck from '@hapi/wreck';

types.expect.type<Plugin<any>>(h2o2.plugin);

async function main() {
  const server = new Server({});
  await server.register(h2o2);

  server.route({
    method: 'GET',
    path: '/hproxyoptions',
    async handler(request, h) {
      // ResponseToolkit augmentation
      // https://github.com/hapijs/h2o2#hproxyoptions
      return h.proxy({ host: 'example.com', port: 80, protocol: 'http' });
    },
  });

  server.route({
    method: 'GET',
    path: '/using-the-host-port-protocol-options',
    handler: {
      // HandlerDecorations augmentation
      // https://github.com/hapijs/h2o2#using-the-host-port-protocol-options
      proxy: {
        host: '10.33.33.1',
        port: '443',
        protocol: 'https',
      },
    },
  });

  server.route({
    method: 'GET',
    path: '/using-the-uri-option',
    handler: {
      // HandlerDecorations augmentation
      // https://github.com/hapijs/h2o2#using-the-uri-option
      proxy: {
        uri: 'https://some.upstream.service.com/that/has?what=you&want=todo',
      },
    },
  });

  server.route({
    method: 'GET',
    path: '/custom-uri-template-values',
    handler: {
      // HandlerDecorations augmentation
      // https://github.com/hapijs/h2o2#custom-uri-template-values
      proxy: {
        uri: '{protocol}://{host}:{port}/go/to/{path}',
      },
    },
  });

  server.route({
    method: 'GET',
    path: '/custom-uri-template-values/{bar}',
    handler: {
      // HandlerDecorations augmentation
      // https://github.com/hapijs/h2o2#custom-uri-template-values
      proxy: {
        uri: 'https://some.upstream.service.com/some/path/to/{bar}',
      },
    },
  });

  server.route({
    method: 'GET',
    path: '/',
    handler: {
      // HandlerDecorations augmentation
      // https://github.com/hapijs/h2o2#using-the-mapuri-and-onresponse-options
      proxy: {
        async mapUri(request) {
          return {
            uri: 'https://some.upstream.service.com/',
          };
        },

        async onRequest(req) {
          types.expect.type<typeof Wreck>(req);
          return req.request('GET', 'https://some.upstream.service.com/');
        },

        async onResponse(err, res, request, h, settings, ttl) {
          types.expect.type<Boom<any> | null>(err);
          types.expect.type<IncomingMessage>(res);
          types.expect.type<Request>(request);
          types.expect.type<ResponseToolkit>(h);
          types.expect.type<h2o2.ProxyHandlerOptions>(settings);
          types.expect.type<number>(ttl);
          return null;
        },
      },
    },
  });

  server.route({
    method: 'GET',
    path: '/',
    handler: {
      proxy: {
        httpClient: {
          // request(method, url, options) {
          //     return axios({method, url })
          // }
        },
      },
    },
  });

  await server.start();
  await server.stop();
}

/**
 * test code added in additional to code in docs.  Demonstrates that for the moment
 * you need flat
 * objects with typing along the way to benefit from typescript catching
 * misspelt, or unsupported keys.
 * This is because of an unknown reason.  Expecting this to work because:
 * "Object literals get special treatment and undergo excess
 * property checking when assigning them to other variables, or passing them
 * as arguments", see github.com/Microsoft/TypeScript
 */

const proxyOptions: h2o2.ProxyHandlerOptions = {
  host: '10.33.33.1',
  port: '443',
  protocol: 'https', // errors correctly if misspelt
};

const badProtocolDemo: ServerRoute = {
  method: 'GET',
  path: '/',
  handler: {
    proxy: {
      host: '10.33.33.1',
      port: '443',
      // port: null // detected as incompatible
    },
  },
};

const replyViaToolkit: ServerRoute = {
  method: 'GET',
  path: '/',
  async handler(req, h): Promise<ResponseObject> {
    return h.proxy({
      host: '10.33.33.1',
      port: '443',
      protocol: 'https',
    });
  },
};
