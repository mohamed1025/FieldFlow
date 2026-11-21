const app = require('../server/index');

module.exports = async function handler(req, res) {
  try {
    await app.initializeFieldFlow();
    return app(req, res);
  } catch (error) {
    console.error('FieldFlow API initialization failed:', error);

    if (res.headersSent) return;

    res.statusCode = 503;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({
      error: 'FieldFlow service initialization failed.'
    }));
  }
};
