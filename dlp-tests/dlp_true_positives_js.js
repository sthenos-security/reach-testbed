/**
 * DLP/PII True Positives — JavaScript
 * =====================================
 * Real PII patterns that MUST be detected across JS contexts.
 * Covers: secrets in objects, API responses, inline configs,
 * GraphQL resolvers, Express middleware, async handlers.
 */

'use strict';

// =============================================================================
// HARDCODED SECRETS (SECRET signal — also DLP)
// =============================================================================

const STRIPE_LIVE_KEY = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
const SENDGRID_API_KEY = 'SG.ngeVJk3iT6KxXnHMecvFUA.abc123def456ghi789jkl012mno345pqr678';
const TWILIO_AUTH_TOKEN = '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d';
const GITHUB_PERSONAL_TOKEN = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456';

// AWS credentials in JS — SHOULD FLAG
const awsConfig = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  region: 'us-east-1',
};

// =============================================================================
// PII: SSN
// =============================================================================

const patientSSN = '123-45-6789';
const employeeRecord = {
  name: 'John Smith',
  ssn: '987-65-4321',
  dob: '1985-03-15',
  department: 'Engineering',
};

function getEmployeeSSN(employeeId) {
  // Hardcoded SSN returned from function — SHOULD FLAG
  return '234-56-7890';
}

// =============================================================================
// PII: Credit Cards
// =============================================================================

const visaCard    = '4532015112830366';
const masterCard  = '5425233430109903';
const amexCard    = '374251018720955';

const paymentData = {
  customerId: 'cust_001',
  cardNumber: '4916338506082832',
  cvv: '737',
  expiry: '12/26',
  billingZip: '94105',
};

// Credit card in API response shape — SHOULD FLAG
const checkoutResponse = {
  status: 'success',
  transaction_id: 'txn_abc123',
  card_used: {
    number: '4532015112830366',
    last4: '0366',
    brand: 'Visa',
  },
};

// =============================================================================
// PII: Personal Emails
// =============================================================================

const customerEmail    = 'jane.doe@gmail.com';
const patientEmail     = 'john.smith.patient@yahoo.com';
const employeePersonal = 'bob.wilson@hotmail.com';

const userProfiles = [
  { id: 1, name: 'Alice', email: 'alice.jones@gmail.com', ssn: '111-22-3334' },
  { id: 2, name: 'Bob',   email: 'bob.brown@outlook.com', card: '5425233430109903' },
];

// =============================================================================
// PII: Phone Numbers
// =============================================================================

const customerPhone  = '(415) 867-5309';
const patientMobile  = '+1-800-555-0199';
const internationalPh = '+44 20 7946 0958';

const contactBook = {
  primary: '650-555-4321',
  emergency: '(415) 555-9876',
  work: '1-888-555-2020',
};

// =============================================================================
// PII: Addresses
// =============================================================================

const homeAddress = '123 Main Street, San Francisco, CA 94105';
const shippingInfo = {
  name: 'Carol Davis',
  street: '456 Oak Avenue',
  city: 'Los Angeles',
  state: 'CA',
  zip: '90210',
  phone: '310-555-7654',
};

// =============================================================================
// PII: Healthcare (HIPAA)
// =============================================================================

const patientRecord = {
  mrn: 'MRN-2026-001234',
  name: 'David Lee',
  dob: '1975-11-08',
  ssn: '345-67-8902',
  diagnosis: 'Atrial fibrillation',
  medication: 'Warfarin 5mg',
  insurance: 'BCBS-1234567890',
  email: 'david.lee.patient@gmail.com',
};

// =============================================================================
// PII: Financial (PCI-DSS)
// =============================================================================

const bankTransfer = {
  fromAccount: '123456789012',
  toAccount:   '987654321098',
  routingNumber: '021000021',
  amount: 50000,
  memo: 'Salary payment',
};

const iban = 'GB29NWBK60161331926819';
const ein  = '12-3456789';

// =============================================================================
// PII: Multi-field combined record (highest severity)
// =============================================================================

const FULL_PII_RECORD = {
  name:        'Eleanor Roosevelt',
  ssn:         '456-78-9013',
  dob:         '1884-10-11',
  email:       'eleanor.roosevelt.personal@gmail.com',
  phone:       '212-555-9876',
  address:     '47 East 65th Street, New York, NY 10065',
  cardNumber:  '4916338506082832',
  cvv:         '923',
  cardExpiry:  '09/27',
  bankAccount: '456789012345',
  routing:     '021000021',
  passport:    'P12345678',
  mrn:         'MRN-2026-099887',
};

// =============================================================================
// PII IN ASYNC / CALLBACK CONTEXT (reachability test)
// =============================================================================

async function fetchPatientData(patientId) {
  // Simulated DB result with PII embedded — SHOULD FLAG
  const result = await Promise.resolve({
    patientId,
    ssn: '567-89-0124',
    name: 'Frances Perkins',
    email: 'frances.perkins@gmail.com',
    phone: '202-555-3456',
  });
  return result;
}

// Express route handler with PII — SHOULD FLAG
function registerRoutes(app) {
  app.get('/api/admin/users', (req, res) => {
    res.json({
      users: [
        { id: 1, email: 'admin.user@gmail.com', ssn: '678-90-1235', card: '4532015112830366' },
      ],
    });
  });

  app.post('/api/payment', (req, res) => {
    const { cardNumber, cvv, expiry } = req.body;
    // PII logged — SHOULD FLAG
    console.log(`Processing card: ${cardNumber}, CVV: ${cvv}, Expiry: ${expiry}`);
    res.json({ status: 'ok', cardUsed: cardNumber });
  });
}

module.exports = { fetchPatientData, registerRoutes };
