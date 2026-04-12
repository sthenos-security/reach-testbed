# frozen_string_literal: true

# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST FILE — CWE-327 FALSE POSITIVE: MD5 FOR EQUALITY COMPARISON
#
# MD5 is used here ONLY for content change detection (checksum comparison).
# This is NOT a security use — the hash is never used for passwords,
# authentication, or signatures.
#
# MD5 for equality comparison (has content changed?) is an acceptable use.
# semgrep flags all MD5 use as CWE-327 regardless of context.
#
# FP cases — Expected: NOT_REACHABLE
#   profile_changed?     — MD5 result used in != comparison only
#   find_matching_profile — MD5 result used in .any? { p == ... } only
#
# TP case — Expected: REACHABLE
#   password_hash — MD5 used for password storage (real CWE-327)
# ============================================================================

require 'digest'
require 'sinatra'

class ProfileManager
  # FP: MD5 for change detection — result used only in != comparison
  # Expected: NOT_REACHABLE
  def profile_changed?(new_template, stored_checksum)
    current_checksum = Digest::MD5.base64digest(new_template)
    current_checksum != stored_checksum
  end

  # FP: MD5 for equality detection — result used only in .any? { == }
  # Expected: NOT_REACHABLE
  def find_matching_profile(template, profiles)
    checksum = Digest::MD5.base64digest(template)
    profiles.any? { |p| p[:checksum] == checksum }
  end

  # TP: MD5 for password storage — real security use, real CWE-327
  # Expected: REACHABLE
  def password_hash(password)
    Digest::MD5.hexdigest(password)
  end
end

mgr = ProfileManager.new

get '/profile/changed' do
  mgr.profile_changed?(params[:template] || '', params[:checksum] || '').to_s
end

post '/auth/login' do
  # TP: MD5 for password — real CWE-327, reachable from HTTP route
  mgr.password_hash(params[:password] || '')
end
