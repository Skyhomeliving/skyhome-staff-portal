// org.js — the organisation this installation belongs to. Every value can be set
// from the environment so the same code can run for any care provider (and for
// the SkyCare OS demo). Defaults are the original Sky Home Living values, so an
// existing installation with none of these variables set behaves exactly as before.
const env = (k, d) => (process.env[k] ?? '').trim() || d;

export const ORG = {
  name: env('ORG_NAME', 'Sky Home Living'),
  legalName: env('ORG_LEGAL_NAME', 'Sky Home Living Limited'),
  shortLegalName: env('ORG_SHORT_LEGAL_NAME', 'Sky Home Living Ltd'),
  address: env('ORG_ADDRESS', 'Ingenuity House, Bickenhill Lane, Birmingham, B37 7HQ'),
  contact: env('ORG_CONTACT', 'info@skyhomeliving.co.uk · www.skyhomeliving.co.uk'),
  defaultManager: env('ORG_DEFAULT_MANAGER', 'Joseph Onus, Managing Director & Nominated Individual'),
  // Must be an address on a Resend-verified domain.
  mailFrom: env('MAIL_FROM', 'Sky Home Living <info@skyhomeliving.co.uk>'),
  adminEmail: env('ADMIN_EMAIL', 'admin@skyhomeliving.co.uk'),
  // Default logos when no custom logo has been uploaded (files in /public).
  loginLogo: env('ORG_LOGIN_LOGO', '/sky-logo.png'),
  markLogo: env('ORG_MARK_LOGO', '/sky-icon.png'),
  favicon: env('ORG_FAVICON', '/favicon.png'),
  // Product line under the organisation name (sidebar) and on the sign-in card.
  sidebarSubtitle: env('PRODUCT_SUBTITLE', 'Compliance Records'),
  loginSubtitle: env('PRODUCT_LOGIN_SUBTITLE', 'Staff Compliance Records'),
};

// Demo installations (SEED_DEMO=1) show a banner and seed fictional staff.
export const IS_DEMO = process.env.SEED_DEMO === '1';
