import { Request, Response, NextFunction } from 'express';

export const SECURE_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'strict' as const,
  path: '/',
} as const;

export function patchCookie(cookie: string): string {
  let c = cookie;
  if (!/;\s*Secure/i.test(c))    c += '; Secure';
  if (!/;\s*HttpOnly/i.test(c))  c += '; HttpOnly';
  if (!/;\s*SameSite=/i.test(c)) c += '; SameSite=Strict';
  return c;
}

export function enforceSecureCookies(_req: Request, res: Response, next: NextFunction): void {
  const orig = res.setHeader.bind(res);
  res.setHeader = (name: string, value: string | number | readonly string[]) => {
    if (name.toLowerCase() === 'set-cookie') {
      const cookies = Array.isArray(value) ? value : [String(value)];
      return orig(name, cookies.map(patchCookie));
    }
    return orig(name, value);
  };
  next();
}

export function enforceHttps(req: Request, res: Response, next: NextFunction): void {
  if (process.env.NODE_ENV !== 'production') return next();
  const proto = (req.headers['x-forwarded-proto'] as string) ?? req.protocol;
  if (proto !== 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    return void res.redirect(301, `https://${req.hostname}${req.originalUrl}`);
  }
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  next();
}

export function applySecureTransport(app: { use: (...args: unknown[]) => void }): void {
  app.use(enforceHttps);
  app.use(enforceSecureCookies);
}
