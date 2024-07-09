# frozen_string_literal: true

module Google
  module Auth
    module Extras
      # This module fixes an issue with ID tokens not automatically refreshing
      # because their expiration is encoded in the JWT.
      module IdentityCredentialRefreshPatch
        def update_token!(*)
          super.tap do
            self.expires_at = decoded_id_token['exp'] if id_token
          end
        end
      end
    end
  end
end
