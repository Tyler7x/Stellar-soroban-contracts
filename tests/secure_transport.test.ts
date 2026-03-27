import { patchCookie, enforceHttps } from '../src/middleware/secure_transport';

describe('patchCookie', () => {
  it('adds Secure flag', () => expect(patchCookie('session=abc')).toContain('Secure'));
  it('adds HttpOnly flag', () => expect(patchCookie('session=abc')).toContain('HttpOnly'));
  it('adds SameSite=Strict', () => expect(patchCookie('session=abc')).toContain('SameSite=Strict'));
  it('does not duplicate flags', () => {
    const c = patchCookie('session=abc; Secure; HttpOnly; SameSite=Strict');
    expect((c.match(/Secure/g) ?? []).length).toBe(1);
  });
});

describe('enforceHttps in production', () => {
  const OLD = process.env.NODE_ENV;
  beforeEach(() => { process.env.NODE_ENV = 'production'; });
  afterEach(()  => { process.env.NODE_ENV = OLD; });

  it('redirects HTTP to HTTPS with 301', () => {
    let status = 0; let url = '';
    const req = { headers: {}, protocol: 'http', hostname: 'example.com', originalUrl: '/test', socket: {} } as any;
    const res = { redirect: (s: number, u: string) => { status = s; url = u; }, setHeader: () => {} } as any;
    enforceHttps(req, res, jest.fn());
    expect(status).toBe(301);
    expect(url).toMatch(/^https:\/\//);
  });

  it('calls next for HTTPS requests', () => {
    const next = jest.fn();
    const req = { headers: { 'x-forwarded-proto': 'https' }, protocol: 'https', hostname: 'example.com', originalUrl: '/test', socket: {} } as any;
    const res = { setHeader: () => {} } as any;
    enforceHttps(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('allows HTTP in development', () => {
    process.env.NODE_ENV = 'development';
    const next = jest.fn();
    const req = { headers: {}, protocol: 'http', hostname: 'example.com', originalUrl: '/test', socket: {} } as any;
    const res = { setHeader: () => {} } as any;
    enforceHttps(req, res, next);
    expect(next).toHaveBeenCalled();
  });
});
