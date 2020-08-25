defmodule KeenAuth.Supervisor do
  use Supervisor

  def start_link(_) do
    Supervisor.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init(_) do
    children = [
      worker(OpenIDConnect.Worker, [generate_openid_configuration()])
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp generate_openid_configuration() do
    Application.get_env(:keen_auth, :clients)
    |> Enum.map(fn {client, config} -> {client, config[:oidc]} end)
  end
end
