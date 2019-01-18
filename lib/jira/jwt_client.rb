require 'atlassian/jwt'

module JIRA
  class JwtClient < HttpClient
    def make_request(http_method, url, body = '', headers = {})
      @http_method = http_method

      super(http_method, url, body, headers)
    end

    def make_multipart_request(url, data, headers = {})
      @http_method = :post

      super(url, data, headers)
    end

    private

    attr_accessor :http_method

    def request_path(url)
      super(url) + "?jwt=#{jwt_header(url)}"
    end

    def jwt_header(url)
      claim = Atlassian::Jwt.build_claims \
        @options[:issuer],
        url,
        http_method.to_s,
        @options[:site],
        (Time.now - 60).to_i,
        (Time.now + (86400)).to_i

      JWT.encode claim, @options[:shared_secret]
    end
  end
end
