defmodule WebAuth.Token do
  require Logger

  alias WebAuth.Helpers.JwtHelpers

  def refresh(refresh_token, client) when is_binary(refresh_token) do
    OpenIDConnect.fetch_tokens(client, %{grant_type: "refresh_token", refresh_token: refresh_token})
  end

  def verify(token, client)

  def verify("Bearer " <> token, client) when is_binary(token) do
    verify(token, client)
  end

  def verify(token, client) when is_binary(token) do
    OpenIDConnect.verify(client, token)
  end
end
