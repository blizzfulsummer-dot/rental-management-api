export function validateEmail(value) {
  if (!value || typeof value !== 'string') {
    return { ok: false, errors: ['email'] };
  }

  const normalized = value.trim().toLowerCase();
  const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized);

  return {
    ok: isValid,
    errors: isValid ? [] : ['email']
  };
}

export function validatePassword(value) {
  if (!value || typeof value !== 'string') {
    return { ok: false, errors: ['password'] };
  }

  const hasMinLength = value.length >= 8;
  const hasUppercase = /[A-Z]/.test(value);
  const hasLowercase = /[a-z]/.test(value);
  const hasNumber = /\d/.test(value);
  const hasSymbol = /[^A-Za-z0-9]/.test(value);
  const ok = hasMinLength && hasUppercase && hasLowercase && hasNumber && hasSymbol;

  return {
    ok,
    errors: ok ? [] : ['password']
  };
}

export function validateNumber(value, fieldName, allowNegative = false) {
  if (value === undefined || value === null) {
    return { ok: false, error: `${fieldName} is required` };
  }
  const num = Number(value);
  if (Number.isNaN(num)) {
    return { ok: false, error: `${fieldName} must be a valid number` };
  }
  if (!allowNegative && num < 0) {
    return { ok: false, error: `${fieldName} cannot be negative` };
  }
  return { ok: true, value: num };
}

export function sanitizeString(value, fieldName, maxLength = 255) {
  if (!value || typeof value !== 'string') {
    return { ok: false, error: `${fieldName} must be a non-empty string` };
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return { ok: false, error: `${fieldName} cannot be empty` };
  }
  if (trimmed.length > maxLength) {
    return { ok: false, error: `${fieldName} cannot exceed ${maxLength} characters` };
  }
  return { ok: true, value: trimmed };
}

export function validateId(value) {
  const num = Number(value);
  if (Number.isNaN(num) || num <= 0 || !Number.isInteger(num)) {
    return { ok: false };
  }
  return { ok: true, value: num };
}

export function validateSignupPayload(payload) {
  const errors = [];
  if (!payload || typeof payload !== 'object') {
    return { ok: false, errors: ['body'] };
  }

  const emailResult = validateEmail(payload.email);
  if (!emailResult.ok) errors.push('email');

  const role = typeof payload.role === 'string' ? payload.role.trim().toLowerCase() : '';
  if (!['admin', 'owner', 'tenant', 'user'].includes(role)) {
    errors.push('role');
  }

  if (role === 'admin' && !payload.code) {
    errors.push('code');
  }

  if (role !== 'admin' && !payload.password && !payload.code) {
    errors.push('password');
  }

  return { ok: errors.length === 0, errors };
}

export function validateLoginPayload(payload) {
  const errors = [];
  const emailResult = validateEmail(payload?.email);
  if (!emailResult.ok) errors.push('email');

  if (!payload?.password || typeof payload.password !== 'string') {
    errors.push('password');
  }

  return { ok: errors.length === 0, errors };
}

export function validateTenantPayload(payload) {
  const errors = [];

  if (!payload || typeof payload !== 'object') {
    return { ok: false, errors: ['body'] };
  }

  const balanceResult = validateNumber(payload.balance, 'balance');
  if (!balanceResult.ok) errors.push('balance');

  const depositResult = validateNumber(payload.deposit, 'deposit');
  if (!depositResult.ok) errors.push('deposit');

  const rentResult = validateNumber(payload.rent_amount, 'rent_amount');
  if (!rentResult.ok) errors.push('rent_amount');

  if (!payload.billing_cycle || typeof payload.billing_cycle !== 'string') {
    errors.push('billing_cycle');
  }

  if (!payload.leased_unit || typeof payload.leased_unit !== 'string') {
    errors.push('leased_unit');
  }

  if (!payload.onboard_date || typeof payload.onboard_date !== 'string') {
    errors.push('onboard_date');
  }

  return { ok: errors.length === 0, errors };
}

export async function parseJsonBody(request) {
  try {
    return { ok: true, data: await request.json() };
  } catch {
    return { ok: false, error: 'Invalid JSON body' };
  }
}
