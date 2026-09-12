import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { performEasmScan } from './server/scanner';
import { generateThreatBriefing } from './server/gemini';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes First
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // EASM Scan endpoint
  app.get('/api/scan', async (req, res) => {
    const domain = req.query.domain as string;
    if (!domain) {
      return res.status(400).json({ error: 'Domain parameter is required' });
    }

    try {
      const results = await performEasmScan(domain);
      return res.json(results);
    } catch (err: any) {
      console.error('Scan error:', err);
      return res.status(500).json({ error: err.message || 'Failed to scan domain' });
    }
  });

  // AI Threat Vector & MITRE Briefing endpoint
  app.post('/api/gemini/threat-briefing', async (req, res) => {
    const scan = req.body;
    if (!scan || !scan.domain) {
      return res.status(400).json({ error: 'Scan data with domain is required' });
    }

    try {
      const briefing = await generateThreatBriefing(scan);
      return res.json(briefing);
    } catch (err: any) {
      console.error('Gemini threat briefing endpoint caught error:', err);
      // Fallback deterministically rather than returning 500 error to browser
      try {
        const { buildDeterministicBriefing } = await import('./server/gemini');
        const fallback = buildDeterministicBriefing(scan, 'Generated via SurfaceTrace offline intelligence engine.');
        return res.json(fallback);
      } catch {
        return res.status(500).json({ error: err.message || 'Failed to generate threat briefing' });
      }
    }
  });

  // Vite middleware for development vs static build in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SurfaceTrace EASM Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
