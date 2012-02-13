require 'net/ldap'
require 'net/ntlm'

module Rack
  class Ntlm
    @@config = {}
    
    def initialize(app, config = {})
      @app = app
      @config = {
        :uri_pattern => /\//,
        :port => 389,
        :search_filter => "(sAMAccountName=%1)",
        :auth_mode => "NTLM",
        :check_domain => true,
        :auth_text => "change it by change config[:auth_text]"
      }.merge(config)

      @@config = @config
    end

    def auth(user)
      ldap = Net::LDAP.new
      ldap.host = @config[:host]
      ldap.port = @config[:port]
      ldap.base = @config[:base]
      ldap.auth @config[:auth][:username], @config[:auth][:password] if @config[:auth]
      !ldap.search(:filter => @config[:search_filter].gsub("%1", user)).empty?
    rescue => e
      false
    end

    def self.auth(user, password)
      ldap = Net::LDAP.new
      ldap.host = @@config[:host]
      ldap.port = @@config[:port]
      ldap.base = @@config[:base]
      ldap.auth user, password
      !ldap.search(:filter => @@config[:search_filter].gsub("%1", user)).empty?
    rescue => e
      false
    end

    def call(env)
      if env['PATH_INFO'] =~ @config[:uri_pattern] && env['HTTP_AUTHORIZATION'].blank?
        return [401, {'WWW-Authenticate' => @config[:auth_mode]}, [@config[:auth_text]]]
      end

      if /^(NTLM|Negotiate) (.+)/ =~ env["HTTP_AUTHORIZATION"]

        message = Net::NTLM::Message.decode64($2)

        if message.type == 1 
          type2 = Net::NTLM::Message::Type2.new
          return [401, {"WWW-Authenticate" => "#{@config[:auth_mode]} " + type2.encode64}, [@config[:auth_text]]]
        end

        if message.type == 3 && env['PATH_INFO'] =~ @config[:uri_pattern]
          user   = Net::NTLM::decode_utf16le(message.user)
          domain = Net::NTLM::decode_utf16le(message.domain)

          matched_domain = @config[:check_domain] ? (domain.present? && @config[:host] =~ /^#{domain}\./i) : true
          if matched_domain && user.present?
            env['REMOTE_USER'] = user
          elsif @config[:fail_path].present?
            return [302, {"Location" => env['REQUEST_URI'].sub(env['PATH_INFO'], @config[:fail_path])}, []]
          end
        end
    	end

      @app.call(env)
    end

  end

end
