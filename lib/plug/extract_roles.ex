defmodule WebAuth.Plug.ExtractRoles do
  @moduledoc """
  If access claims are available for conn then extracts roles claim into separate conn's private variable
  """

  require Logger

  alias Plug.Conn
  alias WebAuth.Request

  def init(opts) do
    %{client: Keyword.fetch!(opts, :client)}
  end

  def call(conn, %{client: client}) do
    with true <- Request.has_claims?(conn, client),
         claims <- Request.get_claims(conn, client),
         extracted_roles when not is_nil(extracted_roles) <- get_in(claims, ["resource_access", client_id(client), "roles"]) do
      Conn.assign(conn, :user_roles, extracted_roles)
    else
      _ -> conn
    end
  end

  defp client_id(client) do
    Application.get_env(:web_auth, :clients)
    |> get_in([client, :oidc, :client_id])
  end
end
