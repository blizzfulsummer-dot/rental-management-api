import test from 'node:test';
import assert from 'node:assert/strict';
import { validateEmail, validatePassword, validateTenantPayload, validateSignupPayload } from '../src/lib/validation.js';

test('validateEmail accepts common addresses', () => {
  assert.equal(validateEmail('user@example.com').ok, true);
  assert.equal(validateEmail('bad').ok, false);
});

test('validatePassword enforces minimum strength', () => {
  assert.equal(validatePassword('weak').ok, false);
  assert.equal(validatePassword('StrongPass1!').ok, true);
});

test('validateSignupPayload accepts owner role', () => {
  const result = validateSignupPayload({
    email: 'owner@example.com',
    role: 'owner',
    password: 'StrongPass1!'
  });

  assert.equal(result.ok, true);
  assert.deepEqual(result.errors, []);
});

test('validateTenantPayload rejects missing tenant fields', () => {
  const result = validateTenantPayload({
    balance: 100,
    deposit: 50,
    rent_amount: 1200,
    billing_cycle: 'monthly',
    leased_unit: '',
    onboard_date: '2026-08-01'
  });

  assert.equal(result.ok, false);
  assert.ok(result.errors.includes('leased_unit'));
});
