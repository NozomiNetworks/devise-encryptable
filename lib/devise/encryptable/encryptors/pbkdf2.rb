begin
  module Devise
    module Encryptable
      module Encryptors
        # = Pbkdf2
        # Uses the Pbkdf2 with SHA512 hash algorithm to encrypt passwords.
        class Pbkdf2 < Base
          def self.compare(encrypted_password, password, stretches, salt, pepper)
            value_to_test = digest(password, stretches, salt, pepper)
            begin
              ActiveSupport::SecurityUtils.fixed_length_secure_compare(encrypted_password, value_to_test)
            rescue ArgumentError
              false
            end
          end

          def self.digest(password, stretches, salt, pepper)
            hash = OpenSSL::Digest.new('SHA512')
            OpenSSL::PKCS5.pbkdf2_hmac(
              password,
              "#{[salt].pack('H*')}#{pepper}",
              (stretches > 1000 ? stretches : 100_000),
              hash.digest_length,
              hash
            ).unpack('H*').first
          end
        end
      end
    end
  end
end
