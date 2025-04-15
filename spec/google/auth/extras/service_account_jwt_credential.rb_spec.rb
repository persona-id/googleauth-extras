# frozen_string_literal: true

RSpec.describe Google::Auth::Extras::ServiceAccountJWTCredential do
  let(:audience) { 'https://random.run.app' }
  let(:email_address) { 'my-sa@my-project.iam.gserviceaccount.com' }
  let(:key) { OpenSSL::PKey::RSA.generate(2048) }

  before do
    Timecop.freeze(Time.at(1676584110))
  end

  describe '#initialize' do
    it 'correctly sets up the credential' do
      credential = described_class.new(
        email_address: email_address,
        target_audience: audience,
      )

      expect(credential.target_audience).to eq(audience)
    end
  end

  describe '#inspect' do
    it 'does not leak sensitive values' do
      credential = described_class.new(
        email_address: email_address,
        target_audience: audience,
      )

      expect(credential.inspect).to eq(
        '#<Google::Auth::Extras::ServiceAccountJWTCredential' \
          ' @expires_at=nil' \
          ' @id_token=nil' \
          ' @jwt_issuer="my-sa@my-project.iam.gserviceaccount.com"' \
          ' @jwt_lifetime=3600' \
          ' @jwt_subject="my-sa@my-project.iam.gserviceaccount.com"' \
          ' @sa_delegates=[]' \
          ' @sa_name="projects/-/serviceAccounts/my-sa@my-project.iam.gserviceaccount.com"' \
          ' @target_audience="https://random.run.app"' \
          '>',
      )

      IAMStubs.stub_sign_jwt(
        name: "projects/-/serviceAccounts/#{email_address}",
        payload: {
          aud: audience,
          exp: 1676587710,
          iat: 1676584110,
          iss: email_address,
          sub: email_address,
        }.to_json,
        response_signed_jwt: JWT.encode(
          {
            aud: audience,
            exp: 1676587710,
            iat: 1676584110,
            iss: email_address,
            sub: email_address,
          },
          key,
          'none',
        ),
      )

      credential.refresh!

      expect(credential.inspect).to eq(
        '#<Google::Auth::Extras::ServiceAccountJWTCredential' \
          ' @expires_at=2023-02-16 22:48:30 +0000' \
          ' @id_token=[REDACTED]' \
          ' @jwt_issuer="my-sa@my-project.iam.gserviceaccount.com"' \
          ' @jwt_lifetime=3600' \
          ' @jwt_subject="my-sa@my-project.iam.gserviceaccount.com"' \
          ' @sa_delegates=[]' \
          ' @sa_name="projects/-/serviceAccounts/my-sa@my-project.iam.gserviceaccount.com"' \
          ' @target_audience="https://random.run.app"' \
          '>',
      )
    end
  end

  context 'token refresh' do
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
          exp: 1676587710,
          iat: 1676584110,
          iss: email_address,
          sub: email_address,
        },
        key,
        'none',
      )

      first_generate_stub = IAMStubs.stub_sign_jwt(
        name: "projects/-/serviceAccounts/#{email_address}",
        payload: {
          aud: audience,
          exp: 1676587710,
          iat: 1676584110,
          iss: email_address,
          sub: email_address,
        }.to_json,
        response_signed_jwt: first_id_token,
      )

      expect(credential.apply({})).not_to be_empty
      expect(credential.id_token).to eq(first_id_token)
      expect(credential.expires_at).to eq(Time.at(1676587710))
      expect(credential.expires_within?(3500)).to be(false)
      expect(credential.expires_within?(4000)).to be(true)
      expect(credential.needs_access_token?).to be(false)

      expect(first_generate_stub).to have_been_requested.once

      Timecop.freeze(Time.now + 3500)

      expect(credential.apply({})).not_to be_empty
      expect(credential.id_token).to eq(first_id_token)
      expect(credential.expires_at).to eq(Time.at(1676587710))
      expect(credential.expires_within?(60)).to be(false)
      expect(credential.expires_within?(120)).to be(true)
      expect(credential.needs_access_token?).to be(false)

      Timecop.freeze(Time.now + 180)

      expect(credential.expires_within?(60)).to be(true)
      expect(credential.needs_access_token?).to be(true)

      expect(first_generate_stub).to have_been_requested.once
      WebMock.reset!

      second_id_token = JWT.encode(
        {
          aud: audience,
          exp: 1676591390,
          iat: 1676587790,
          iss: email_address,
          sub: email_address,
        },
        key,
        'none',
      )

      second_generate_stub = IAMStubs.stub_sign_jwt(
        name: "projects/-/serviceAccounts/#{email_address}",
        payload: {
          aud: audience,
          exp: 1676591390,
          iat: 1676587790,
          iss: email_address,
          sub: email_address,
        }.to_json,
        response_signed_jwt: second_id_token,
      )

      expect(credential.apply({})).not_to be_empty
      expect(credential.id_token).to eq(second_id_token)
      expect(credential.expires_at).to eq(Time.at(1676591390))
      expect(credential.expires_within?(3500)).to be(false)
      expect(credential.expires_within?(4000)).to be(true)
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
          exp: 1676587710,
          iat: 1676584110,
          iss: email_address,
          sub: email_address,
        },
        key,
        'none',
      )

      generate_stub = IAMStubs.stub_sign_jwt(
        name: "projects/-/serviceAccounts/#{email_address}",
        payload: {
          aud: audience,
          exp: 1676587710,
          iat: 1676584110,
          iss: email_address,
          sub: email_address,
        }.to_json,
        response_signed_jwt: id_token,
      )

      expect(credential.apply({})).not_to be_empty
      expect(credential.id_token).to eq(id_token)
      expect(credential.expires_at).to eq(Time.at(1676587710))
      expect(credential.expires_within?(3500)).to be(false)
      expect(credential.expires_within?(4000)).to be(true)
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

      id_token = JWT.encode(
        {
          aud: audience,
          exp: 1676587710,
          iat: 1676584110,
          iss: email_address,
          sub: email_address,
        },
        key,
        'none',
      )

      generate_stub = IAMStubs.stub_sign_jwt(
        delegates: %w[
          projects/-/serviceAccounts/intermediate-sa-one@my-project.iam.gserviceaccount.com
          projects/-/serviceAccounts/intermediate-sa-two@my-project.iam.gserviceaccount.com
        ],
        name: "projects/-/serviceAccounts/#{email_address}",
        payload: {
          aud: audience,
          exp: 1676587710,
          iat: 1676584110,
          iss: email_address,
          sub: email_address,
        }.to_json,
        response_signed_jwt: id_token,
      )

      expect(credential.apply({})).not_to be_empty
      expect(credential.id_token).to eq(id_token)
      expect(credential.expires_at).to eq(Time.at(1676587710))
      expect(credential.expires_within?(3500)).to be(false)
      expect(credential.expires_within?(4000)).to be(true)
      expect(credential.needs_access_token?).to be(false)

      expect(generate_stub).to have_been_requested
    end

    it 'supports custom issuers & subjects' do
      credential = described_class.new(
        email_address: email_address,
        issuer: 'my-issuer',
        subject: 'my-subject',
        target_audience: audience,
      )

      id_token = JWT.encode(
        {
          aud: audience,
          exp: 1676587710,
          iat: 1676584110,
          iss: 'my-issuer',
          sub: 'my-subject',
        },
        key,
        'none',
      )

      generate_stub = IAMStubs.stub_sign_jwt(
        name: "projects/-/serviceAccounts/#{email_address}",
        payload: {
          aud: audience,
          exp: 1676587710,
          iat: 1676584110,
          iss: 'my-issuer',
          sub: 'my-subject',
        }.to_json,
        response_signed_jwt: id_token,
      )

      expect(credential.apply({})).not_to be_empty
      expect(credential.id_token).to eq(id_token)
      expect(credential.expires_at).to eq(Time.at(1676587710))
      expect(credential.expires_within?(3500)).to be(false)
      expect(credential.expires_within?(4000)).to be(true)
      expect(credential.needs_access_token?).to be(false)

      expect(generate_stub).to have_been_requested
    end
  end
end
