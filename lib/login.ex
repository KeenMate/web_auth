defmodule KeenAuth.Login do
  def uri(client, params \\ %{}) do
    OpenIDConnect.authorization_uri(client, params)
  end
end
