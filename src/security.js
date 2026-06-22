import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

export const securityMiddleware = (app) => {
  app.set('trust proxy', 1);
  app.use(helmet({
    contentSecurityPolicy: false
  }));
  // Limit only the POST (the actual sign-in attempt) — viewing or
  // refreshing the GET /login page must not count toward the limit.
  app.post('/login', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.LOGIN_RATELIMIT_MAX || 5),
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many login attempts. Please wait 15 minutes.'
  }));
};
