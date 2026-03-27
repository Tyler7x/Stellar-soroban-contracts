import { issueRefreshToken, validateRefreshToken, revokeToken, RefreshTokenError } from '../src/auth/refresh_token';

const USER = 'user-123';
const IP_A = '203.0.113.10';
const IP_B = '198.51.100.42';

test('issues a unique token each time', () => {
  expect(issueRefreshToken(USER, IP_A)).not.toBe(issueRefreshToken(USER, IP_A));
});

test('validates token from same IP', () => {
  const token = issueRefreshToken(USER, IP_A);
  expect(validateRefreshToken(token, IP_A)).toBe(USER);
});

test('throws IP_MISMATCH for different IP', () => {
  const token = issueRefreshToken(USER, IP_A);
  try { validateRefreshToken(token, IP_B); } catch (e) {
    expect((e as RefreshTokenError).code).toBe('IP_MISMATCH');
  }
});

test('revokes token after IP mismatch', () => {
  const token = issueRefreshToken(USER, IP_A);
  try { validateRefreshToken(token, IP_B); } catch {}
  try { validateRefreshToken(token, IP_A); } catch (e) {
    expect((e as RefreshTokenError).code).toBe('TOKEN_REVOKED');
  }
});

test('throws TOKEN_REVOKED for manually revoked token', () => {
  const token = issueRefreshToken(USER, IP_A);
  revokeToken(token);
  try { validateRefreshToken(token, IP_A); } catch (e) {
    expect((e as RefreshTokenError).code).toBe('TOKEN_REVOKED');
  }
});

test('throws TOKEN_NOT_FOUND for unknown token', () => {
  try { validateRefreshToken('fake-token', IP_A); } catch (e) {
    expect((e as RefreshTokenError).code).toBe('TOKEN_NOT_FOUND');
  }
});

test('normalises IPv4-mapped IPv6 addresses', () => {
  const token = issueRefreshToken(USER, '::ffff:' + IP_A);
  expect(validateRefreshToken(token, IP_A)).toBe(USER);
});
