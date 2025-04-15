# frozen_string_literal: true

RSpec.describe Google::Auth::Extras do
  before do
    Timecop.freeze(Time.at(1676584110))
  end

  shared_context 'impersonated authorization (access token)' do
    let(:base_credentials) { Signet::OAuth2::Client.new }
    let(:email_address) { 'my-sa@my-project.iam.gserviceaccount.com' }
    let(:lifetime) { '120s' }
    let(:scopes) { %w[a b c] }

    let(:delegate_email_addresses) do
      %w[
        intermediate-sa-one@my-project.iam.gserviceaccount.com
        intermediate-sa-two@my-project.iam.gserviceaccount.com
      ]
    end

    before do
      allow(base_credentials).to receive(:access_token).and_return('abc123')
    end
  end

  shared_context 'impersonated authorization (id token)' do
    let(:audience) { 'https://random.run.app' }
    let(:base_credentials) { Signet::OAuth2::Client.new }
    let(:email_address) { 'my-sa@my-project.iam.gserviceaccount.com' }

    let(:delegate_email_addresses) do
      %w[
        intermediate-sa-one@my-project.iam.gserviceaccount.com
        intermediate-sa-two@my-project.iam.gserviceaccount.com
      ]
    end

    before do
      allow(base_credentials).to receive(:access_token).and_return('abc123')
    end
  end

  shared_context 'service account jwt authorization' do
    let(:audience) { 'https://random.run.app' }
    let(:base_credentials) { Signet::OAuth2::Client.new }
    let(:email_address) { 'my-sa@my-project.iam.gserviceaccount.com' }

    let(:delegate_email_addresses) do
      %w[
        intermediate-sa-one@my-project.iam.gserviceaccount.com
        intermediate-sa-two@my-project.iam.gserviceaccount.com
      ]
    end

    before do
      allow(base_credentials).to receive(:access_token).and_return('abc123')
    end
  end

  shared_context 'static authorization' do
    let(:access_token) { SecureRandom.hex(100) }

    let!(:info_stub) do
      TokenInfoStubs.stub_lookup_success(access_token: access_token, expires_in: 290)
    end
  end

  describe '.impersonated_authorization' do
    context 'for an access token' do
      subject do
        described_class.impersonated_authorization(
          base_credentials: base_credentials,
          delegate_email_addresses: delegate_email_addresses,
          email_address: email_address,
          lifetime: lifetime,
          scope: scopes,
        )
      end

      include_context 'impersonated authorization (access token)'

      it 'creates the authorization' do
        expect(subject).to be_a(Google::Auth::Extras::ImpersonatedCredential)
        expect(subject.access_token).to be_nil
        expect(subject.id_token).to be_nil
        expect(subject.token_type).to eq(:access_token)
      end

      it 'triggers a warning from the GCP SDK' do
        allow(Kernel).to receive(:warn)

        Google::Cloud.configure.storage.credentials = subject

        expect(Kernel).to have_received(:warn).with(/Invalid value #<Google::Auth::Extras::ImpersonatedCredential .* for key :credentials\. Setting anyway\./)
      end

      context 'with a quota project' do
        subject do
          described_class.impersonated_authorization(
            base_credentials: base_credentials,
            delegate_email_addresses: delegate_email_addresses,
            email_address: email_address,
            lifetime: lifetime,
            quota_project_id: 'other-project',
            scope: scopes,
          )
        end

        it 'creates the authorization' do
          expect(subject).to be_a(Google::Auth::Extras::ImpersonatedCredential)
          expect(subject.access_token).to be_nil
          expect(subject.id_token).to be_nil
          expect(subject.quota_project_id).to eq('other-project')
          expect(subject.token_type).to eq(:access_token)
        end
      end
    end

    context 'for an id token' do
      subject do
        described_class.impersonated_authorization(
          base_credentials: base_credentials,
          delegate_email_addresses: delegate_email_addresses,
          email_address: email_address,
          include_email: true,
          target_audience: audience,
        )
      end

      include_context 'impersonated authorization (id token)'

      it 'creates the authorization' do
        expect(subject).to be_a(Google::Auth::Extras::ImpersonatedCredential)
        expect(subject.access_token).to be_nil
        expect(subject.id_token).to be_nil
        expect(subject.token_type).to eq(:id_token)
      end

      it 'triggers a warning from the GCP SDK' do
        allow(Kernel).to receive(:warn)

        Google::Cloud.configure.storage.credentials = subject

        expect(Kernel).to have_received(:warn).with(/Invalid value #<Google::Auth::Extras::ImpersonatedCredential .* for key :credentials\. Setting anyway\./)
      end

      context 'with a quota project' do
        subject do
          described_class.impersonated_authorization(
            base_credentials: base_credentials,
            delegate_email_addresses: delegate_email_addresses,
            email_address: email_address,
            include_email: true,
            quota_project_id: 'other-project',
            target_audience: audience,
          )
        end

        it 'creates the authorization' do
          expect(subject).to be_a(Google::Auth::Extras::ImpersonatedCredential)
          expect(subject.access_token).to be_nil
          expect(subject.id_token).to be_nil
          expect(subject.quota_project_id).to eq('other-project')
          expect(subject.token_type).to eq(:id_token)
        end
      end
    end
  end

  describe '.impersonated_credential' do
    context 'for an access token' do
      subject do
        described_class.impersonated_credential(
          base_credentials: base_credentials,
          delegate_email_addresses: delegate_email_addresses,
          email_address: email_address,
          lifetime: lifetime,
          scope: scopes,
        )
      end

      include_context 'impersonated authorization (access token)'

      it 'creates the credential' do
        expect(subject).to be_a(Google::Auth::Credentials)
        expect(subject.client).to be_a(Google::Auth::Extras::ImpersonatedCredential)
        expect(subject.client.access_token).to be_nil
        expect(subject.client.id_token).to be_nil
        expect(subject.client.token_type).to eq(:access_token)
      end

      it 'does not trigger a warning from the GCP SDK' do
        allow(Kernel).to receive(:warn)

        Google::Cloud.configure.storage.credentials = subject

        expect(Kernel).not_to have_received(:warn)
      end

      context 'with a quota project' do
        subject do
          described_class.impersonated_credential(
            base_credentials: base_credentials,
            delegate_email_addresses: delegate_email_addresses,
            email_address: email_address,
            lifetime: lifetime,
            quota_project_id: 'other-project',
            scope: scopes,
          )
        end

        it 'creates the credential' do
          expect(subject).to be_a(Google::Auth::Credentials)
          expect(subject.client).to be_a(Google::Auth::Extras::ImpersonatedCredential)
          expect(subject.client.access_token).to be_nil
          expect(subject.client.id_token).to be_nil
          expect(subject.client.quota_project_id).to eq('other-project')
          expect(subject.client.token_type).to eq(:access_token)
        end
      end
    end

    context 'for an id token' do
      subject do
        described_class.impersonated_credential(
          base_credentials: base_credentials,
          delegate_email_addresses: delegate_email_addresses,
          email_address: email_address,
          include_email: true,
          target_audience: audience,
        )
      end

      include_context 'impersonated authorization (id token)'

      it 'creates the credential' do
        expect(subject).to be_a(Google::Auth::Credentials)
        expect(subject.client).to be_a(Google::Auth::Extras::ImpersonatedCredential)
        expect(subject.client.access_token).to be_nil
        expect(subject.client.id_token).to be_nil
        expect(subject.client.token_type).to eq(:id_token)
      end

      it 'does not trigger a warning from the GCP SDK' do
        allow(Kernel).to receive(:warn)

        Google::Cloud.configure.storage.credentials = subject

        expect(Kernel).not_to have_received(:warn)
      end

      context 'with a quota project' do
        subject do
          described_class.impersonated_credential(
            base_credentials: base_credentials,
            delegate_email_addresses: delegate_email_addresses,
            email_address: email_address,
            include_email: true,
            quota_project_id: 'other-project',
            target_audience: audience,
          )
        end

        it 'creates the credential' do
          expect(subject).to be_a(Google::Auth::Credentials)
          expect(subject.client).to be_a(Google::Auth::Extras::ImpersonatedCredential)
          expect(subject.client.access_token).to be_nil
          expect(subject.client.id_token).to be_nil
          expect(subject.client.quota_project_id).to eq('other-project')
          expect(subject.client.token_type).to eq(:id_token)
        end
      end
    end
  end

  describe '.service_account_jwt_authorization' do
    subject do
      described_class.service_account_jwt_authorization(
        base_credentials: base_credentials,
        delegate_email_addresses: delegate_email_addresses,
        email_address: email_address,
        target_audience: audience,
      )
    end

    include_context 'service account jwt authorization'

    it 'creates the authorization' do
      expect(subject).to be_a(Google::Auth::Extras::ServiceAccountJWTCredential)
      expect(subject.access_token).to be_nil
      expect(subject.id_token).to be_nil
      expect(subject.token_type).to eq(:id_token)
    end

    it 'triggers a warning from the GCP SDK' do
      allow(Kernel).to receive(:warn)

      Google::Cloud.configure.storage.credentials = subject

      expect(Kernel).to have_received(:warn)
        .with(/Invalid value #<Google::Auth::Extras::ServiceAccountJWTCredential .* for key :credentials\. Setting anyway\./)
    end
  end

  describe '.service_account_jwt_credential' do
    subject do
      described_class.service_account_jwt_credential(
        base_credentials: base_credentials,
        delegate_email_addresses: delegate_email_addresses,
        email_address: email_address,
        target_audience: audience,
      )
    end

    include_context 'service account jwt authorization'

    it 'creates the credential' do
      expect(subject).to be_a(Google::Auth::Credentials)
      expect(subject.client).to be_a(Google::Auth::Extras::ServiceAccountJWTCredential)
      expect(subject.client.access_token).to be_nil
      expect(subject.client.id_token).to be_nil
      expect(subject.client.token_type).to eq(:id_token)
    end

    it 'does not trigger a warning from the GCP SDK' do
      allow(Kernel).to receive(:warn)

      Google::Cloud.configure.storage.credentials = subject

      expect(Kernel).not_to have_received(:warn)
    end
  end

  describe '.static_authorization' do
    subject { described_class.static_authorization(access_token) }

    include_context 'static authorization'

    it 'creates the authorization' do
      expect(subject).to be_a(Google::Auth::Extras::StaticCredential)
      expect(subject.access_token).to eq(access_token)

      expect(info_stub).to have_been_requested
    end

    it 'triggers a warning from the GCP SDK' do
      allow(Kernel).to receive(:warn)

      Google::Cloud.configure.storage.credentials = subject

      expect(Kernel).to have_received(:warn).with(/Invalid value #<Google::Auth::Extras::StaticCredential .* for key :credentials\. Setting anyway\./)
    end

    context 'with a quota project' do
      subject { described_class.static_authorization(access_token, quota_project_id: 'other-project') }

      it 'creates the authorization' do
        expect(subject).to be_a(Google::Auth::Extras::StaticCredential)
        expect(subject.access_token).to eq(access_token)
        expect(subject.quota_project_id).to eq('other-project')

        expect(info_stub).to have_been_requested
      end
    end
  end

  describe '.static_credential' do
    subject { described_class.static_credential(access_token) }

    include_context 'static authorization'

    it 'creates the credential' do
      expect(subject).to be_a(Google::Auth::Credentials)
      expect(subject.client).to be_a(Google::Auth::Extras::StaticCredential)
      expect(subject.client.access_token).to eq(access_token)

      expect(info_stub).to have_been_requested
    end

    it 'does not trigger a warning from the GCP SDK' do
      allow(Kernel).to receive(:warn)

      Google::Cloud.configure.storage.credentials = subject

      expect(Kernel).not_to have_received(:warn)
    end

    context 'with a quota project' do
      subject { described_class.static_credential(access_token, quota_project_id: 'other-project') }

      it 'creates the credential' do
        expect(subject).to be_a(Google::Auth::Credentials)
        expect(subject.client).to be_a(Google::Auth::Extras::StaticCredential)
        expect(subject.client.access_token).to eq(access_token)
        expect(subject.client.quota_project_id).to eq('other-project')

        expect(info_stub).to have_been_requested
      end
    end
  end
end
