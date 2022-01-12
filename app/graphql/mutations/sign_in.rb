module Mutations
  class SignIn < BaseMutation
    argument :email, String, required: true
    argument :password, String, required: true
    

    field :token, String, null: true
    field :user, Types::UserType, null: true

    def resolve(
      email:,
      password:
    )

      raise UserPasswordNotFound unless password

      user = User.find_by(email: email)

      raise UserPasswordNotFound unless user

      raise UserPasswordNotFound unless user.authenticate(password)

      payload = { token: user.id }

      token = JWT.encode payload, ENV["HMAC_SECRET"], 'HS256'

      { 
        user: user, 
        token: token 
      }
    end
  end
end
