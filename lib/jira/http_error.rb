require 'forwardable'
module JIRA
  class HTTPError < StandardError
    extend Forwardable

    def_instance_delegators :@response, :code
    attr_reader :response, :message

    def initialize(response)
      @response = response
      msg = response.respond_to?(:message) ? response.message : nil
      @message = if msg.nil? || msg.empty?
                   response.respond_to?(:body) ? response.body : nil
                 else
                   msg
                 end
    end
  end
end
