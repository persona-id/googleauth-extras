# frozen_string_literal: true

RSpec.describe Google::Auth::Extras::ImpersonatedCredential do
  let(:audience) { 'https://random.run.app' }
  let(:email_address) { 'my-sa@my-project.iam.gserviceaccount.com' }
  let(:scopes) { %w[a b c] }

  before do
    Timecop.freeze(Time.at(1676584110))
  end

  describe '#initialize' do
    it 'correctly sets up the credential' do
      credential = described_class.new(
        email_address: email_address,
        scope: scopes,
      )

      expect(credential.scope).to eq(%w[a b c])
    end

    it 'normalizes the scope' do
      credential = described_class.new(
        email_address: email_address,
        scope: 'a b c',
      )

      expect(credential.scope).to eq(%w[a b c])
    end

    it 'requires scope or target_audience' do
      expect do
        described_class.new(
          email_address: email_address,
          scope: nil,
        )
      end.to raise_error(ArgumentError, 'Must provide scope or target_audience')

      expect do
        described_class.new(
          email_address: email_address,
          scope: '    ',
        )
      end.to raise_error(ArgumentError, 'Must provide scope or target_audience')

      expect do
        described_class.new(
          email_address: email_address,
          scope: [],
        )
      end.to raise_error(ArgumentError, 'Must provide scope or target_audience')

      expect do
        described_class.new(
          email_address: email_address,
          target_audience: nil,
        )
      end.to raise_error(ArgumentError, 'Must provide scope or target_audience')
    end

    it 'requires only one of scope or target_audience' do
      expect do
        described_class.new(
          email_address: email_address,
          scope: 'a',
          target_audience: 'b',
        )
      end.to raise_error(ArgumentError, 'Must provide scope or target_audience, not both')
    end

    it 'only supports passing valid options for an access token' do
      expect do
        described_class.new(
          include_email: false,
          email_address: email_address,
          scope: 'a b c',
        )
      end.to raise_error(ArgumentError, 'Can only provide include_email when using target_audience')

      expect do
        described_class.new(
          include_email: true,
          email_address: email_address,
          scope: 'a b c',
        )
      end.to raise_error(ArgumentError, 'Can only provide include_email when using target_audience')
    end

    it 'only supports passing valid options for an ID token' do
      expect do
        described_class.new(
          email_address: email_address,
          lifetime: '120s',
          target_audience: 'b',
        )
      end.to raise_error(ArgumentError, 'Cannot provide lifetime when using target_audience')
    end
  end

  describe '#inspect' do
    context 'for an access token' do
      it 'does not leak sensitive values' do
        credential = described_class.new(
          email_address: email_address,
          scope: scopes,
        )

        expect(credential.inspect).to eq(
          '#<Google::Auth::Extras::ImpersonatedCredential' \
            ' @access_token=nil' \
            ' @expires_at=nil' \
            ' @impersonate_delegates=[]' \
            ' @impersonate_lifetime=nil' \
            ' @impersonate_name="projects/-/serviceAccounts/my-sa@my-project.iam.gserviceaccount.com"' \
            '>',
        )

        IAMStubs.stub_generate_access_token(
          name: "projects/-/serviceAccounts/#{email_address}",
          scope: %w[a b c],
          response_access_token: SecureRandom.hex(100),
          response_expire_time: (Time.now + 600).utc.to_datetime.rfc3339,
        )

        credential.refresh!

        expect(credential.inspect).to eq(
          '#<Google::Auth::Extras::ImpersonatedCredential' \
            ' @access_token=[REDACTED]' \
            ' @expires_at=2023-02-16 21:58:30 +0000' \
            ' @impersonate_delegates=[]' \
            ' @impersonate_lifetime=nil' \
            ' @impersonate_name="projects/-/serviceAccounts/my-sa@my-project.iam.gserviceaccount.com"' \
            '>',
        )
      end
    end
  end

  context 'token refresh' do
    context 'for an access token' do
      it 'refreshes when necessary' do
        credential = described_class.new(
          email_address: email_address,
          scope: scopes,
        )

        expect(credential.access_token).to be_nil
        # no expires_at triggers this to be false
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.needs_access_token?).to be(true)

        first_access_token = SecureRandom.hex(100)

        first_generate_stub = IAMStubs.stub_generate_access_token(
          name: "projects/-/serviceAccounts/#{email_address}",
          scope: %w[a b c],
          response_access_token: first_access_token,
          response_expire_time: (Time.now + 600).to_datetime.rfc3339,
        )

        expect(credential.apply({})).not_to be_empty
        expect(credential.access_token).to eq(first_access_token)
        expect(credential.expires_at).to eq(Time.at(1676584710))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(1000)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        expect(first_generate_stub).to have_been_requested

        Timecop.freeze(Time.now + 500)

        expect(credential.apply({})).not_to be_empty
        expect(credential.access_token).to eq(first_access_token)
        expect(credential.expires_at).to eq(Time.at(1676584710))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(120)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        Timecop.freeze(Time.now + 200)

        expect(credential.expires_within?(60)).to be(true)
        expect(credential.needs_access_token?).to be(true)

        expect(first_generate_stub).to have_been_requested.once
        WebMock.reset!

        second_access_token = SecureRandom.hex(100)

        second_generate_stub = IAMStubs.stub_generate_access_token(
          name: "projects/-/serviceAccounts/#{email_address}",
          scope: %w[a b c],
          response_access_token: second_access_token,
          response_expire_time: (Time.now + 600).to_datetime.rfc3339,
        )

        expect(credential.apply({})).not_to be_empty
        expect(credential.access_token).to eq(second_access_token)
        expect(credential.expires_at).to eq(Time.at(1676585410))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(1000)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        expect(second_generate_stub).to have_been_requested.once
      end

      it 'supports base credentials' do
        base_credentials = Signet::OAuth2::Client.new

        allow(base_credentials).to receive(:access_token).and_return('abc123')

        credential = described_class.new(
          base_credentials: base_credentials,
          email_address: email_address,
          scope: scopes,
        )

        expect(credential.access_token).to be_nil
        # no expires_at triggers this to be false
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.needs_access_token?).to be(true)

        access_token = SecureRandom.hex(100)

        generate_stub = IAMStubs.stub_generate_access_token(
          name: "projects/-/serviceAccounts/#{email_address}",
          scope: %w[a b c],
          response_access_token: access_token,
          response_expire_time: (Time.now + 600).to_datetime.rfc3339,
        )

        expect(credential.apply({})).not_to be_empty
        expect(credential.access_token).to eq(access_token)
        expect(credential.expires_at).to eq(Time.at(1676584710))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(1000)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        expect(base_credentials).to have_received(:access_token).at_least(:once)
        expect(generate_stub).to have_been_requested
      end

      it 'supports credential lifetime' do
        credential = described_class.new(
          email_address: email_address,
          lifetime: '120s',
          scope: scopes,
        )

        expect(credential.access_token).to be_nil
        # no expires_at triggers this to be false
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.needs_access_token?).to be(true)

        access_token = SecureRandom.hex(100)

        generate_stub = IAMStubs.stub_generate_access_token(
          lifetime: '120s',
          name: "projects/-/serviceAccounts/#{email_address}",
          scope: %w[a b c],
          response_access_token: access_token,
          response_expire_time: (Time.now + 120).to_datetime.rfc3339,
        )

        expect(credential.apply({})).not_to be_empty
        expect(credential.access_token).to eq(access_token)
        expect(credential.expires_at).to eq(Time.at(1676584230))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(180)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        expect(generate_stub).to have_been_requested
      end

      it 'supports delegation' do
        credential = described_class.new(
          delegate_email_addresses: %w[
            intermediate-sa-one@my-project.iam.gserviceaccount.com
            intermediate-sa-two@my-project.iam.gserviceaccount.com
          ],
          email_address: email_address,
          scope: scopes,
        )

        expect(credential.access_token).to be_nil
        # no expires_at triggers this to be false
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.needs_access_token?).to be(true)

        access_token = SecureRandom.hex(100)

        generate_stub = IAMStubs.stub_generate_access_token(
          delegates: %w[
            projects/-/serviceAccounts/intermediate-sa-one@my-project.iam.gserviceaccount.com
            projects/-/serviceAccounts/intermediate-sa-two@my-project.iam.gserviceaccount.com
          ],
          name: "projects/-/serviceAccounts/#{email_address}",
          scope: %w[a b c],
          response_access_token: access_token,
          response_expire_time: (Time.now + 600).to_datetime.rfc3339,
        )

        expect(credential.apply({})).not_to be_empty
        expect(credential.access_token).to eq(access_token)
        expect(credential.expires_at).to eq(Time.at(1676584710))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(1000)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        expect(generate_stub).to have_been_requested
      end
    end

    context 'for an id token' do
      let(:key) { OpenSSL::PKey::RSA.generate(2048) }

      it 'refreshes when necessary' do
        credential = described_class.new(
          email_address: email_address,
          target_audience: audience,
        )

        expect(credential.id_token).to be_nil
        # no expires_at triggers this to be false
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.needs_access_token?).to be(true)

        first_id_token = JWT.encode(
          {
            aud: audience,
            exp: (Time.now + 600).to_i,
          },
          key,
          'none',
        )

        first_generate_stub = IAMStubs.stub_generate_id_token(
          audience: audience,
          name: "projects/-/serviceAccounts/#{email_address}",
          response_token: first_id_token,
        )

        expect(credential.apply({})).not_to be_empty
        expect(credential.id_token).to eq(first_id_token)
        expect(credential.expires_at).to eq(Time.at(1676584710))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(1000)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        expect(first_generate_stub).to have_been_requested

        Timecop.freeze(Time.now + 500)

        expect(credential.apply({})).not_to be_empty
        expect(credential.id_token).to eq(first_id_token)
        expect(credential.expires_at).to eq(Time.at(1676584710))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(120)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        Timecop.freeze(Time.now + 200)

        expect(credential.expires_within?(60)).to be(true)
        expect(credential.needs_access_token?).to be(true)

        expect(first_generate_stub).to have_been_requested.once
        WebMock.reset!

        second_id_token = JWT.encode(
          {
            aud: audience,
            exp: (Time.now + 600).to_i,
          },
          key,
          'none',
        )

        second_generate_stub = IAMStubs.stub_generate_id_token(
          audience: audience,
          name: "projects/-/serviceAccounts/#{email_address}",
          response_token: second_id_token,
        )

        expect(credential.apply({})).not_to be_empty
        expect(credential.id_token).to eq(second_id_token)
        expect(credential.expires_at).to eq(Time.at(1676585410))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(1000)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        expect(second_generate_stub).to have_been_requested.once
      end

      it 'supports base credentials' do
        base_credentials = Signet::OAuth2::Client.new

        allow(base_credentials).to receive(:access_token).and_return('abc123')

        credential = described_class.new(
          base_credentials: base_credentials,
          email_address: email_address,
          target_audience: audience,
        )

        expect(credential.id_token).to be_nil
        # no expires_at triggers this to be false
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.needs_access_token?).to be(true)

        id_token = JWT.encode(
          {
            aud: audience,
            exp: (Time.now + 600).to_i,
          },
          key,
          'none',
        )

        generate_stub = IAMStubs.stub_generate_id_token(
          audience: audience,
          name: "projects/-/serviceAccounts/#{email_address}",
          response_token: id_token,
        )

        expect(credential.apply({})).not_to be_empty
        expect(credential.id_token).to eq(id_token)
        expect(credential.expires_at).to eq(Time.at(1676584710))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(1000)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        expect(base_credentials).to have_received(:access_token).at_least(:once)
        expect(generate_stub).to have_been_requested
      end

      it 'supports delegation' do
        credential = described_class.new(
          delegate_email_addresses: %w[
            intermediate-sa-one@my-project.iam.gserviceaccount.com
            intermediate-sa-two@my-project.iam.gserviceaccount.com
          ],
          email_address: email_address,
          target_audience: audience,
        )

        expect(credential.id_token).to be_nil
        # no expires_at triggers this to be false
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.needs_access_token?).to be(true)

        id_token = JWT.encode(
          {
            aud: audience,
            exp: (Time.now + 600).to_i,
          },
          key,
          'none',
        )

        generate_stub = IAMStubs.stub_generate_id_token(
          audience: audience,
          delegates: %w[
            projects/-/serviceAccounts/intermediate-sa-one@my-project.iam.gserviceaccount.com
            projects/-/serviceAccounts/intermediate-sa-two@my-project.iam.gserviceaccount.com
          ],
          name: "projects/-/serviceAccounts/#{email_address}",
          response_token: id_token,
        )

        expect(credential.apply({})).not_to be_empty
        expect(credential.id_token).to eq(id_token)
        expect(credential.expires_at).to eq(Time.at(1676584710))
        expect(credential.expires_within?(60)).to be(false)
        expect(credential.expires_within?(1000)).to be(true)
        expect(credential.needs_access_token?).to be(false)

        expect(generate_stub).to have_been_requested
      end
    end
  end
end
