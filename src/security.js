import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

export const securityMiddleware = (app) => {
  // Behind Railway's proxy: trust the first hop so req.ip / rate-limiting use
  // the real client address (from X-Forwarded-For), not the proxy's.
  app.set('trust proxy', 1);

  app.use(helmet({
    // Sensible CSP. The portal renders server-side HTML that relies on inline
    // event handlers (onclick=…) and inline <style>/style attributes, so script
    // and style sources must allow 'unsafe-inline'. Everything else is locked to
    // same-origin; framing and plugins are denied outright.
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        // The server-rendered pages use inline event handlers (onclick=,
        // onsubmit=) for row navigation and delete confirmations; helmet's
        // default of script-src-attr 'none' would block those, so allow them.
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        fontSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        formAction: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        // Don't force https upgrades — keeps local/dev (plain http) working;
        // production still gets https via HSTS below.
        upgradeInsecureRequests: null,
      },
    },
    // X-Frame-Options: DENY (belt-and-braces with frame-ancestors 'none').
    frameguard: { action: 'deny' },
    // HSTS: 1 year, apply to subdomains. Browsers only honour this over https,
    // so it's a no-op on plain-http local dev.
    hsts: { maxAge: 31536000, includeSubDomains: true },
  }));

  // Per-IP rate limits. These complement (they do not replace) the per-account
  // lockout in auth.js. Limit only the POSTs so viewing/refreshing a GET page
  // never counts toward the limit.
  app.post('/login', rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: Number(process.env.LOGIN_RATELIMIT_MAX || 10),
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many login attempts. Please wait 15 minutes.',
  }));
  // Throttle password-reset requests to prevent email-bombing an address.
  app.post('/forgot', rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: Number(process.env.FORGOT_RATELIMIT_MAX || 10),
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many reset requests. Please wait 15 minutes.',
  }));
  // Registration is invite-only; a low hourly cap blunts invite-code guessing.
  app.post('/register', rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: Number(process.env.REGISTER_RATELIMIT_MAX || 3),
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many attempts. Please wait an hour and try again.',
  }));
};
