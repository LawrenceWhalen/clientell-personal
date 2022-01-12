module Mutations
  class SignIn < BaseMutation
    class AuthProviderSignInData < Types::BaseInputObject
      argument :credentials, Types::AuthProviderCredentialsInput, required: false
    end
      argument :auth_provider, AuthProviderSignInData, required: false

      field :token, String, null: true
      field :user, Types::UserType, null: true

    def resolve(auth_provider: nil)

      raise UserPasswordNotFound unless auth_provider

      user = User.find_by(email: auth_provider&.[](:credentials)&.[](:email))

      raise UserPasswordNotFound unless user

      raise UserPasswordNotFound unless user.authenticate(auth_provider&.[](:credentials)&.[](:password))

      payload = { token: user.id }

      token = JWT.encode payload, ENV["HMAC_SECRET"], 'HS256'

      { 
        user: user, 
        token: token 
      }
    end
  end
end
