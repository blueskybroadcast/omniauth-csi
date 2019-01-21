require 'omniauth-oauth2'
require 'builder'

module OmniAuth
  module Strategies
    class CSI < OmniAuth::Strategies::OAuth2
      option :name, 'csi'

      option :client_options, { login_page_url: 'MUST BE PROVIDED' }
      option :app_options, { app_event_id: nil }

      uid { info[:uid] }

      info { raw_user_info }

      def request_phase
        slug = session['omniauth.params']['origin'].delete('/')
        redirect options.client_options.login_page_url + '?redirectURL=' + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        slug = request.params['slug']
        account = Account.find_by(slug: slug)
        app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + slug
        self.env['omniauth.redirect_url'] = request.params['redirect_url'].presence
        self.env['omniauth.app_event_id'] = app_event.id
        call_app!
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash
      end

      def raw_user_info
        {
          uid: request.params['uid'],
          first_name: request.params['first_name'],
          last_name: request.params['last_name'],
          email: request.params['email'],
          username: request.params['username'],
          is_member: request.params['is_member'],
          member_type: request.params['member_type']
        }
      end
    end
  end
end
