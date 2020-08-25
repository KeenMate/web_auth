defmodule KeenAuth.Plug.EnsureRoles do
  @default_operation :and

  @moduledoc """
  Makes sure that specified roles are provided in user's roles.
  This requires that ExtractRoles plug has already been called before in pipeline.
  Available options:
  roles (default #{inspect([])}), operation (default #{inspect(@default_operation)})
  """

  require Logger

  alias Plug.Conn

  @type opts() :: %{roles: [String.t()], operation: atom()}

  @spec init(keyword()) :: opts()
  def init(opts) do
    %{
      roles: Keyword.get(opts, :roles, []) |> Enum.map(&normalize_role/1),
      operation: Keyword.get(opts, :op, @default_operation)
    }
  end

  @spec call(Conn.t(), opts()) :: Conn.t()
  def call(conn, %{roles: []}) do
    conn
  end

  def call(conn, %{roles: roles, operation: op}) do
    with {:ok, extracted_roles} <- Map.fetch(conn.assigns, :user_roles) do
      Logger.info("Extracted roles: #{inspect(extracted_roles)}. Roles to ensure: #{inspect(roles)}")

      extracted_roles
      |> check_roles(op, roles)
      |> handle_authorization(conn, extracted_roles)
    else
      _ -> set_forbidden(conn)
    end
  end

  #  def call(conn, %{roles: roles, operation: op, client_id: client_id}) when is_binary(client_id) do
  #    with claims when not is_nil(claims) <- get_access_claims(conn),
  #         extracted_roles when not is_nil(extracted_roles) <-
  #           get_in(claims, ["resource_access", client_id, "roles"]) do
  #      Logger.info(
  #        "Extracted roles: #{inspect(extracted_roles)}. Roles to ensure: #{inspect(roles)}"
  #      )
  #
  #      extracted_roles
  #      |> check_roles(op, roles)
  #      |> handle_authorization(conn, extracted_roles)
  #    else
  #      _ -> set_forbidden(conn)
  #    end
  #  end

  #  defp get_access_claims(conn) do
  #    Tokens.get_access_claims_from_private(conn) || Tokens.get_access_claims_from_session(conn)
  #  end

  defp handle_authorization(true, conn, extracted_roles) do
    conn
    |> Conn.assign(:user_roles, extracted_roles)
  end

  defp handle_authorization(false, conn, _extracted_roles) do
    set_forbidden(conn)
  end

  defp check_roles(current_roles, op, roles) do
    check_roles(current_roles, nil, op, roles)
  end

  defp check_roles(_current_roles, true, _op, []), do: true

  defp check_roles(_current_roles, _acc, _op, []), do: false

  defp check_roles(_current_roles, false, :and, _roles_to_check), do: false

  defp check_roles(current_roles, acc, :and, [role_to_check | other_roles_to_check])
       when acc in [nil, true] do
    check_roles(
      current_roles,
      normalize_role(role_to_check) in current_roles,
      :and,
      other_roles_to_check
    )
  end

  defp check_roles(_current_roles, true, :or, _roles_to_check), do: true

  defp check_roles(current_roles, acc, :or, [role_to_check | other_roles_to_check])
       when acc in [nil, false] do
    check_roles(
      current_roles,
      normalize_role(role_to_check) in current_roles,
      :or,
      other_roles_to_check
    )
  end

  def normalize_role(role) when is_atom(role) do
    role
    |> Atom.to_string()
    |> String.downcase()
  end

  def normalize_role(role) when is_binary(role) do
    role
    |> String.downcase()
  end

  defp set_forbidden(conn) do
    Conn.put_status(conn, 403)
  end
end
