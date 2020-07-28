defmodule WebAuth.Plug.ExtractRoles do
  @moduledoc """
  If access claims are available for conn then extracts roles claim into separate conn's private variable
  """

  require Logger

  alias Plug.Conn
  alias WebAuth.Tokens

  @type opts() :: %{client_id: String.t()}

  @spec init(keyword()) :: opts()
  def init(opts) do
    %{
      client_id: Keyword.fetch!(opts, :client_id)
    }
  end

  def call(conn, %{client_id: client_id}) do
    with true <- Tokens.access_claims_in_private?(conn),
         claims when not is_nil(claims) <- Tokens.get_access_claims_from_private(conn),
         extracted_roles when not is_nil(extracted_roles) <-
           get_in(claims, ["resource_access", client_id, "roles"]) do
      conn
      |> Conn.assign(:user_roles, extracted_roles)
    else
      _ -> conn
    end
  end
end
