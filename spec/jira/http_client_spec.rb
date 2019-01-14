require 'spec_helper'

describe JIRA::HttpClient do
  subject(:client) { JIRA::HttpClient.new(client_options) }

  let(:client_options) { JIRA::Client::DEFAULT_OPTIONS.merge(JIRA::HttpClient::DEFAULT_OPTIONS) }
  let(:body) { nil }
  let(:headers) { double }
  let(:basic_auth_http_conn) { double }
  let(:request){  double }
  let(:response) { double('response') }

  before do
    allow(response).to receive(:kind_of?).with(Net::HTTPSuccess).and_return(true)
    allow(client).to receive(:basic_auth_http_conn).and_return(basic_auth_http_conn)
    allow(basic_auth_http_conn).to receive(:request).with(request).and_return(response)
  end

  describe '#basic_auth_http_conn' do
    before do
      allow(client).to receive(:basic_auth_http_conn).and_call_original
    end

    it 'creates an instance of Net:HTTP' do
      expect(subject.basic_auth_http_conn.class).to eq(Net::HTTP)
    end
  end

  describe '#make_request' do
    RSpec.shared_examples 'Http methods tests' do
      it 'makes a valid request' do
        %i[delete get head].each do |method|
          expect(Net::HTTP.const_get(method.to_s.capitalize)).to receive(:new).with('/path', headers).and_return(request)
          expect(client.make_request(method, '/path', nil, headers)).to eq(response)
        end

        %i[post put].each do |method|
          expect(Net::HTTP.const_get(method.to_s.capitalize)).to receive(:new).with('/path', headers).and_return(request)
          expect(request).to receive(:body=).with('').and_return(request)
          expect(client.make_request(method, '/path', '', headers)).to eq(response)
        end
      end
    end

    context 'for a basic client' do
      subject { client.make_request(:get, request_url, body, headers) }

      let(:http_method) { :get }
      let(:request_url) { '/foo' }

      before do
        allow(Net::HTTP::Get).to receive(:new).with(request_url, headers).and_return(request)
        allow(client).to receive(:basic_auth_http_conn).and_return(basic_auth_http_conn)
      end

      it 'performs a basic http client request' do
        expect(request).to receive(:basic_auth).with(client.options[:username], client.options[:password]).and_return(request)

        subject
      end

      it 'performs a basic http client request with a full domain' do
        expect(request).to receive(:basic_auth).with(client.options[:username], client.options[:password]).and_return(request)

        subject
      end

      context 'for all http methods' do
        before do
          expect(request).to receive(:basic_auth).with(client.options[:username], client.options[:password]).exactly(5).times.and_return(request)
          expect(basic_auth_http_conn).to receive(:request).exactly(5).times.with(request).and_return(response)
        end

        include_examples 'Http methods tests'
      end
    end

    context 'for a basic cookie client' do
      let(:client_options) { JIRA::Client::DEFAULT_OPTIONS.merge(JIRA::HttpClient::DEFAULT_OPTIONS).merge(use_cookies: true) }

      context 'for all http methods' do
        before do
          expect(request).to receive(:basic_auth).with(client.options[:username], client.options[:password]).exactly(5).times.and_return(request)
          expect(basic_auth_http_conn).to receive(:request).exactly(5).times.with(request).and_return(response)
          expect(response).to receive(:get_fields).with('set-cookie').exactly(5).times
        end

        include_examples 'Http methods tests'
      end
    end

    context 'for a basic cookie client with additional cookies' do
      let(:client_options) do
        JIRA::Client::DEFAULT_OPTIONS.merge(JIRA::HttpClient::DEFAULT_OPTIONS).merge(
            use_cookies: true,
            additional_cookies: %w(sessionToken=abc123 internal=true)
        )
      end

      context 'for all http methods' do
        before do
          expect(request).to receive(:basic_auth).with(client.options[:username], client.options[:password]).exactly(5).times.and_return(request)
          expect(request).to receive(:add_field).with('Cookie', 'sessionToken=abc123; internal=true').exactly(5).times
          expect(response).to receive(:get_fields).with('set-cookie').exactly(5).times
          expect(basic_auth_http_conn).to receive(:request).exactly(5).times.with(request).and_return(response)
        end

        include_examples 'Http methods tests'
      end
    end
  end

  describe '#make_multipart_request' do
    subject { client.make_multipart_request(path, data, headers) }

    let(:headers) { { 'X-Atlassian-Token' => 'no-check' } }
    let(:data) { {} }
    let(:path) { '/foo' }


    before do
      allow(request).to receive(:basic_auth)
      allow(response).to receive(:get_fields).with('set-cookie')
      allow(Net::HTTP::Post::Multipart).to receive(:new).with(path, data, headers).and_return(request)
    end

    it 'performs a basic http client request' do
      expect(request).to receive(:basic_auth).with(client.options[:username], client.options[:password]).and_return(request)

      subject
    end

    it 'makes a correct HTTP request' do
      expect(basic_auth_http_conn).to receive(:request).with(request).and_return(response)
      expect(response).to receive(:is_a?).with(Net::HTTPOK)

      subject
    end
  end

  describe '#make_cookie_auth_request' do
    subject { client.make_cookie_auth_request }

    let(:client_options) do
      JIRA::Client::DEFAULT_OPTIONS.merge(JIRA::HttpClient::DEFAULT_OPTIONS).merge(
          use_cookies: true,
          context_path: '/context'
      )
    end
    let(:headers) { { 'Content-Type' => 'application/json' } }
    let(:expected_path) { '/context/rest/auth/1/session' }
    let(:expected_body) { '{"username":"","password":""}' }

    before do
      allow(request).to receive(:basic_auth)
      allow(response).to receive(:get_fields).with('set-cookie')
    end

    it 'makes a correct HTTP request' do
      expect(basic_auth_http_conn).to receive(:request).with(request).and_return(response)
      expect(request).to receive(:body=).with(expected_body)
      expect(Net::HTTP.const_get(:post.to_s.capitalize)).to receive(:new).with(expected_path, headers).and_return(request)

      subject
    end
  end

  describe '#uri' do
    subject { client.uri }

    let(:uri) { URI.parse(client.options[:site]) }

    it 'returns a URI' do
      expect(subject).to eq(uri)
    end
  end

  describe '#http_conn' do
    subject { client.http_conn(uri) }

    let(:uri) { double }
    let(:host) { double }
    let(:port) { double }
    let(:http_conn) { double }

    before do
      allow(Net::HTTP).to receive(:new).with(host, port).and_return(http_conn)
      allow(uri).to receive(:host).and_return(host)
      allow(uri).to receive(:port).and_return(port)
      allow(http_conn).to receive(:use_ssl=).with(client.options[:use_ssl]).and_return(http_conn)
      allow(http_conn).to receive(:verify_mode=).with(client.options[:ssl_verify_mode]).and_return(http_conn)
      allow(http_conn).to receive(:read_timeout=).with(client.options[:read_timeout]).and_return(http_conn)
    end

    it 'sets up a http connection with options' do
      expect(client.http_conn(uri)).to eq(http_conn)
    end

    context 'for a client with certificates' do
      let(:client_options) do
        JIRA::Client::DEFAULT_OPTIONS.merge(JIRA::HttpClient::DEFAULT_OPTIONS).merge(
            use_client_cert: true,
            cert: 'public certificate contents',
            key: 'private key contents'
        )
      end
      before do
        expect(http_conn).to receive(:cert=).with(client.options[:cert])
        expect(http_conn).to receive(:key=).with(client.options[:key])
      end

      it 'uses the certificates' do
        expect(client.http_conn(uri)).to eq(http_conn)
      end
    end
  end
end
