import { request } from 'node:http';

const host = process.env.LIGHTNING_HOST || 'localhost:4400';
// The API root returns its typed 404 without allocating an anonymous session.
for (const [path, status] of [['/', 200], ['/api/v1', 404]]) {
  await new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: Number(process.env.PORT ?? 4400), path, headers: { host } }, (res) => {
      res.setEncoding('utf8');
      let body = '';
      res.on('data', (chunk) => { if (path === '/api/v1') body += chunk; });
      res.on('end', () => {
        try {
          if (res.statusCode !== status) throw new Error(`${path}: ${res.statusCode}`);
          if (path === '/api/v1' && JSON.parse(body).error?.code !== 'not_found') {
            throw new Error('Expected the API not_found response');
          }
          resolve();
        } catch (error) { reject(error); }
      });
      res.on('error', reject);
    });
    req.setTimeout(3000, () => req.destroy(new Error('Healthcheck timed out')));
    req.on('error', reject);
    req.end();
  });
}
