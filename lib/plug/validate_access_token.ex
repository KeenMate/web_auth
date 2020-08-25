defmodule KeenAuth.Plug.ValidateAccessToken do
  require Logger

  alias KeenAuth.Request
  alias KeenAuth.Claims

  def init(params) do
    %{
      audience: Keyword.fetch!(params, :audience),
      client: Keyword.fetch!(params, :client)
    }
  end

  def call(conn, %{audience: audience, client: client}) when is_binary(audience) do
    with true <- Request.has_claims?(conn, client),
         claims <- Request.get_claims(conn, client),
         :ok <- Claims.validate(claims, [:exp, {:aud, audience}], client) do
      conn
    else
      {:error, reason} ->
        Logger.debug("[ValidateAccessToken] Claims invalid: #{inspect(reason)}")
        Request.delete_claims(conn, client)

      _ ->
        conn
    end
  end
end
