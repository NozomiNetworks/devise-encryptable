require "test_helper"

class Encryptors < ActiveSupport::TestCase
  include Support::Swappers

  test 'should match a password created by authlogic' do
    authlogic = "b623c3bc9c775b0eb8edb218a382453396fec4146422853e66ecc4b6bc32d7162ee42074dcb5f180a770dc38b5df15812f09bbf497a4a1b95fe5e7d2b8eb7eb4"
    encryptor = Devise::Encryptable::Encryptors::AuthlogicSha512.digest('123mudar', 20, 'usZK_z_EAaF61Gwkw-ed', '')
    assert_equal authlogic, encryptor
  end

  test 'should match a password created by pbkdf2' do
    pbkdf2 = "9d9274895609f1ad7f076dd66b97912c2308deb34355d0678ce1100c61b1a31b95210ed15e11a7455fe64c59b8f8610e34ee1ebfd2eb968a883746fc37458a96"
    encryptor = Devise::Encryptable::Encryptors::Pbkdf2.digest('123mudar', 100_000, 'usZK_z_EAaF61Gwkw-ed', '')
    assert_equal pbkdf2, encryptor
  end

  test 'should not rais exception when comparing strings with different lengths' do
    refute Devise::Encryptable::Encryptors::Pbkdf2.compare('s1', 's2long', 10, 'salt', 'pepper')
  end
  test 'pbkdf2 doesnt allow low stretches' do
    encryptor_low = Devise::Encryptable::Encryptors::Pbkdf2.digest('123mudar', 20, 'usZK_z_EAaF61Gwkw-ed', '')
    encryptor = Devise::Encryptable::Encryptors::Pbkdf2.digest('123mudar', 100_000, 'usZK_z_EAaF61Gwkw-ed', '')
    encryptor_high = Devise::Encryptable::Encryptors::Pbkdf2.digest('123mudar', 120_000, 'usZK_z_EAaF61Gwkw-ed', '')
    assert_equal encryptor_low, encryptor
    refute_equal encryptor_high, encryptor
  end

  test 'should match a password created by restful_authentication' do
    restful_authentication = "93110f71309ce91366375ea44e2a6f5cc73fa8d4"
    encryptor = Devise::Encryptable::Encryptors::RestfulAuthenticationSha1.digest('123mudar', 10, '48901d2b247a54088acb7f8ea3e695e50fe6791b', 'fee9a51ec0a28d11be380ca6dee6b4b760c1a3bf')
    assert_equal restful_authentication, encryptor
  end

  test 'should match a password created by clearance' do
    clearance = "0f40bbae18ddefd7066276c3ef209d40729b0378"
    encryptor = Devise::Encryptable::Encryptors::ClearanceSha1.digest('123mudar', nil, '65c58472c207c829f28c68619d3e3aefed18ab3f', nil)
    assert_equal clearance, encryptor
  end

  test 'digest should raise NotImplementedError if not implemented in subclass' do
    c = Class.new(Devise::Encryptable::Encryptors::Base)
    assert_raise(NotImplementedError) do
      c.digest('quux', 10, 'foo', 'bar')
    end
  end

  Devise::ENCRYPTORS_LENGTH.each do |key, value|
    test "should have length #{value} for #{key.inspect}" do
      swap Devise, :encryptor => key do
        encryptor = Devise::Encryptable::Encryptors.const_get(key.to_s.classify)
        assert_equal value, encryptor.digest('a', 4, encryptor.salt(4), nil).size
      end
    end
  end
end
