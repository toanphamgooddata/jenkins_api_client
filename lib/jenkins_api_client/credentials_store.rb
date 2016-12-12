require 'jenkins_api_client/urihelper'
require 'xmlsimple'
require 'httpi'

module JenkinsApi
  class Client
    # This class communicates with the Jenkins "/credential" API to add delete
    # credentials
    #
    class CredentialsStore
      def initialize(client, *plugin_settings)
        @client = client
        @logger = @client.logger
      end

      def add_credential_passwd(id, domain="_", scope, username, password, description="")
        if has_credentail_id(id)
          @logger.error("Credential ID #{id} exists")
          return false
        end
        if not has_domain(domain)
          @logger.error("Domain #{domain} doesn't exist")
          return false
        end
        json_data = "json={\n"
        json_data += "  \"\": \"0\",\n"
        json_data += "  \"credentials\": {\n"
        json_data += "    \"scope\": \"GLOBAL\",\n"
        json_data += "    \"id\": \"#{id}\",\n"
        json_data += "    \"username\": \"#{username}\",\n"
        json_data += "    \"$class\": \"com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl\",\n"
        json_data += "    \"password\": \"#{password}\",\n"
        json_data += "    \"description\": \"#description\",\n"
        json_data += "  }\n"
        json_data += "}"
        
        @client.post_data("credentails/store/system/domain/#{domain}/createCredentials", json_data)
      end

      def add_credential_private_key(id, domain="_", scope, username, file_path, description="")
         if has_credentail_id(id)
          @logger.error("Credential ID #{id} exists")
          return false
        end
        if not has_domain(domain)
          @logger.error("Domain #{domain} doesn't exist")
          return false
        end
        json_data = "json={\n"
        json_data += "  \"\": \"0\",\n"
        json_data += "  \"credentials\": {\n"
        json_data += "    \"scope\": \"GLOBAL\",\n"
        json_data += "    \"id\": \"#{id}\",\n"
        json_data += "    \"username\": \"#{username}\",\n"
        json_data += "    \"$class\": \"com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl\",\n"
        json_data += "    \"privateKeySource\": {\n"
        json_data += "      \"$class\": \"com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$FileOnMasterPrivateKeySource\",\n"
        json_data += "      \"privateKeyFile\": \"#{file_path}\",\n"
        json_data += "    },\n"
        json_data += "    \"description\": \"#description\",\n"
        json_data += "  }\n"
        json_data += "}"

        @client.post_data("credentails/store/system/domain/#{domain}/createCredentials", json_data)
      end

      def remove_credential(id)
        if not has_credential_id(id)
          return true
        end
        return @client.api_post_request("credentials/store/system/domain/_/credential/#{id}/doDelete")
      end

      def load_credentials_store()
        if @cs
          return @cs
        end
        # @logger.debug("GET #{VIEW_URL}")
        response = @client.api_get_request("credentials", :url_suffix => "api/xml?depth=5")
        @logger.debug("Return from #{VIEW_URL} ${response}")
        # @cs = XmlSimple.xml_in(responsei, :ForceArray => false)
      end

      def has_credential_id(id)
        load_credentials_store()
        @cs["stores"]["system"]["domains"].each do |domain_name, domain|
          domain["credential"].each do | credentiail |
            if credential["id"] == id then
              return true
            end
          end
        end
        return false
      end

      def has_domain(domain="_")
        load_credential_store()
        @cs["stores"]["system"]["domains"].each do |domain_name, domain|
          if domain_name == domain
            return true
          end
        end
        return false
      end
    end
  end
end
