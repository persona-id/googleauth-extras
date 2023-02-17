# googleauth-extras

**Disclaimer: This gem is not sponsored by Google.**

The [googleauth](https://github.com/googleapis/google-auth-library-ruby) currently lacks support for all the authentication schemes supported in Python and the `gcloud` CLI. This gem aims to support additional schemes like:

- Impersonated credentials
- Static credentials

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'googleauth-extras'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install googleauth-extras

## Usage

### Impersonated Credentials

If you'd like to have credentials that act as a different service account, you can setup the credentials with:

```ruby
Google::Apis::DriveV3::DriveService.new.tap do |ds|
  ds.authorization = Google::Auth::Extras.impersonated_credential(
    email_address: 'my-sa@my-project.iam.gserviceaccount.com',
    scope: [
      Google::Apis::SheetsV4::AUTH_DRIVE,
    ],
  )
end
```

You can optionally specify the following additional options:

- `base_credentials`: The credentials to use to make the impersonation call. If not specified, uses the standard SDK credential resolution process.
- `delegate_email_addresses`: If there are intermediate service accounts that need to be impersonated using [delegation](https://cloud.google.com/iam/docs/create-short-lived-credentials-delegated#sa-credentials-permissions), the list of email addresses.
- `lifetime`: The desired lifetime [in seconds](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken), defaulting to 1h.

### Static Credentials

If you'd like to use a static access token, you can setup the credentials with:

```ruby
# Old API Client
Google::Apis::RequestOptions.default.authorization = Google::Auth::Extras.static_credential('my-access-token')
# New API Client
Google::Cloud.configure.credentials = Google::Auth::Extras.static_credential('my-access-token')
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/persona-id/googleauth-extras.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
