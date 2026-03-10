'use strict';
// NOT_REACHABLE: SECRET — file NEVER required by server.js
const STRIPE_KEY    = 'sk_live_jsNR_xxxxxxxxxxxxxxxxxxxxxxxxxxx'; // NR
const GITHUB_TOKEN  = 'ghp_jsNRxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; // NR
const AWS_KEY_ID    = 'AKIAJSNR0000EXAMPLE';                       // NR
const AWS_SECRET    = 'jsNR/K7MDENGbPxRfiCYEXAMPLEKEY000000000'; // NR
const JWT_SECRET    = 'jwt_super_secret_jsNR_DO_NOT_EXPOSE';       // NR

function getStripeKey() { return STRIPE_KEY; }
function getAwsCreds() { return { id: AWS_KEY_ID, secret: AWS_SECRET }; }
