# frozen_string_literal: true

# Ruby Test App - REACHABLE testbed
#
# REACHABLE CVEs:
#   - CVE-2022-24836 (nokogiri ReDoS) — triggered via /parse
#   - CVE-2022-23633 (rails info disclosure) — triggered via /render
#   - CVE-2022-30122 (rack multipart DoS) — triggered via /upload
#   - GHSA-gp7f-rwcx-9369 (jwt algorithm confusion) — triggered via /auth
#
# NOT_REACHABLE:
#   - dead_nokogiri_parse — never called from routes
#   - dead_jwt_verify — never called from routes

require "sinatra"
require "nokogiri"
require "jwt"
require "rack"
require "json"

# ===========================================================================
# Hardcoded secrets (SECRET signal)
# ===========================================================================
JWT_SECRET       = "super_secret_jwt_key_12345"
AWS_ACCESS_KEY   = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL     = "postgresql://admin:db_password_abc123@prod-db.example.com/app"

# ===========================================================================
# REACHABLE: nokogiri CVE-2022-24836 (ReDoS via HTML4 parser)
# Called from GET /parse route — REACHABLE
# ===========================================================================
def parse_html(content)
  doc = Nokogiri::HTML4(content)
  doc.css("title").first&.text
end

# ===========================================================================
# REACHABLE: jwt GHSA-gp7f-rwcx-9369 (algorithm confusion)
# Accepts 'alg' from user payload — attacker can switch HS256→none
# ===========================================================================
def verify_token(token)
  # Vulnerable: does not specify algorithm — accepts any including 'none'
  JWT.decode(token, JWT_SECRET)
end

# ===========================================================================
# REACHABLE: rack multipart handling CVE-2022-30122
# Rack is loaded by Sinatra; any multipart POST route is affected
# ===========================================================================
post "/upload" do
  content_type :json
  file = params[:file]
  { received: file&.dig(:filename) }.to_json
end

# ===========================================================================
# Routes (entrypoints from HTTP)
# ===========================================================================
get "/parse" do
  content_type :json
  html = params[:html] || "<html><title>test</title></html>"
  { title: parse_html(html) }.to_json
end

post "/auth" do
  content_type :json
  body = JSON.parse(request.body.read)
  result = verify_token(body["token"])
  { user: result[0] }.to_json
rescue StandardError => e
  status 401
  { error: e.message }.to_json
end

get "/health" do
  content_type :json
  { status: "ok" }.to_json
end

# ===========================================================================
# NOT_REACHABLE: dead code — never called from any route handler
# ===========================================================================
def dead_nokogiri_xslt(input)
  # Uses nokogiri XSLT — CVE-2022-29181 — but unreachable
  Nokogiri::XSLT(input)
end

def dead_jwt_verify_rs256(token)
  # Would verify with RS256 but this function is never called
  pub_key = OpenSSL::PKey::RSA.new("PLACEHOLDER")
  JWT.decode(token, pub_key, true, algorithms: ["RS256"])
end
