# frozen_string_literal: true

RSpec.describe Google::Auth::Extras::ImpersonatedCredential do
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

    it 'requires a scope' do
      expect do
        described_class.new(
          email_address: email_address,
          scope: nil,
        )
      end.to raise_error(described_class::MissingScope)

      expect do
        described_class.new(
          email_address: email_address,
          scope: '    ',
        )
      end.to raise_error(described_class::MissingScope)

      expect do
        described_class.new(
          email_address: email_address,
          scope: [],
        )
      end.to raise_error(described_class::MissingScope)
    end
  end

  context 'token refresh' do
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
end
