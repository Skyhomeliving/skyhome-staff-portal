import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

export const securityMiddleware = (app) => {
  app.set('trust proxy', 1);
  app.use(helmet({
    contentSecurityPolicy: false
  }));
  app.use('/login', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts. Please wait 15 minutes.'
  }));
};
