defmodule WebAuth.Plug.ValidateAccessToken do
  alias WebAuth.Tokens
  alias WebAuth.Helpers.JwtHelpers

  require Logger

  def init(params) do
    %{
      audience: Keyword.fetch!(params, :audience)
    }
  end

  def call(conn, %{audience: audience}) when is_binary(audience) do
    with true <- Tokens.access_claims_in_private?(conn) do
      case JwtHelpers.validate_claims(Tokens.get_access_claims_from_private(conn), audience) do
        :ok -> conn
        # invalid claims, removing from conn
        {:error, _} ->
          Logger.debug("[ValidateAccessToken] Claims invalid, removing from conn")
          Tokens.remove_claims_from_private(conn)
      end
    else
      # no claims in conn
      _ -> conn
    end
  end
end
